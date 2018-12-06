/*  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <varmgmt.h>
#include <NvMemoryLayout.h>

//
// Offsets and lengths (Note: naturally NV_BLOCK_SIZE aligned!)
//
#define SECUREBOOT_VAR_RESERVED_START   (0)
#define SECUREBOOT_VAR_RESERVED_LEN     (32 * 1024)

#define BOOT_VAR_RESERVED_START         (SECUREBOOT_VAR_RESERVED_START + SECUREBOOT_VAR_RESERVED_LEN)
#define BOOT_VAR_RESERVED_LEN           (8 * 1024)

#define PRIVATE_AUTH_VAR_RESERVED_START (BOOT_VAR_RESERVED_START + BOOT_VAR_RESERVED_LEN)
#define PRIVATE_AUTH_VAR_RESERVED_LEN   (4 * 1024)

#define TOTAL_RESERVED_LEN  (SECUREBOOT_VAR_RESERVED_LEN + BOOT_VAR_RESERVED_LEN + PRIVATE_AUTH_VAR_RESERVED_LEN)
#define GENERAL_VAR_START   (PRIVATE_AUTH_VAR_RESERVED_START + PRIVATE_AUTH_VAR_RESERVED_LEN)
#define GENERAL_VAR_LEN     (NV_AUTHVAR_SIZE - (TOTAL_RESERVED_LEN))

// 
// Auth Var storage layout
//
VTYPE_INFO VarInfo[VTYPE_END] =
{
    {
        L"SecureBootVariables", VTYPE_SECUREBOOT,
        //SECUREBOOT_VAR_RESERVED_START, SECUREBOOT_VAR_RESERVED_LEN,
        { 0 }, TRUE,
    },
    {
        L"BootVariables", VTYPE_BOOT,
        //BOOT_VAR_RESERVED_START, BOOT_VAR_RESERVED_LEN,
        { 0 }, TRUE,
    },
    {
        L"Runtime Private Authenticated Variables", VTYPE_PVT_AUTHENTICATED,
        //PRIVATE_AUTH_VAR_RESERVED_START, PRIVATE_AUTH_VAR_RESERVED_LEN,
        { 0 }, TRUE,
    },
    {
        L"General Space", VTYPE_GENERAL,
        //GENERAL_VAR_START, GENERAL_VAR_LEN,
        { 0 }, TRUE,
    },
    {
        L"Volatile Variable", VTYPE_VOLATILE,   // VOLATILE AUTH VARS ARE NOT PERSISTED!
        //NULL, 0,                                // VOLATILE AUTH VARS ARE NOT PERSISTED!
        { 0 }, FALSE,                           // VOLATILE AUTH VARS ARE NOT PERSISTED!
    }
};

LIST_ENTRY MemoryReclamationList = {0};

//
// Offsets/ptrs for NV vriable storage
//
static UINT_PTR s_nextFree = NV_AUTHVAR_START;
static const UINT_PTR s_nvLimit = NV_AUTHVAR_START + NV_AUTHVAR_SIZE;

//
// Handy empty GUID const
//
GUID GUID_NULL = { 0, 0, 0,{ 0, 0, 0, 0, 0, 0, 0, 0 } };

//
// Memory Management Prototypes
//
VOID
TrackOffset(
    PUEFI_VARIABLE pVar
);

VOID
UpdateOffsets(
    UINT_PTR NVOffset,
    UINT32 ShrinkAmount
);

VOID
DumpAuthvarMemoryImpl(VOID);

VOID
MergeAdjacentNodes (
    PUEFI_VARIABLE FirstNode
);

BOOLEAN
ReclaimNode(
    PUEFI_VARIABLE Node
);

UINT32
AuthVarInitStorage(
    UINT_PTR StartingOffset,
    BOOLEAN ReInitialize
);

//
// Helper function prototype(s)
//

static
BOOLEAN
CompareEntries(
    PCUNICODE_STRING     Name,      // IN
    PCGUID               Guid,      // IN
    PUEFI_VARIABLE       Var        // IN
);

static
BOOLEAN
GetVariableType(
    PCWSTR      VarName,    // IN
    PCGUID      VendorGuid, // IN
    ATTRIBUTES  Attributes, // IN
    PVARTYPE    VarType     // OUT
);

static
BOOLEAN
IsSecureBootVar(
    PCWSTR  VarName,        // IN
    PCGUID  VendorGuid      // IN
);

//
// Auth Var Storage Maintenance Functions
//

/**
 * Memory Management:
 * 
 * When a variable is deleted or shrunk it will leave gaps. These gaps
 * are cleared during initialization of the NV memory.
 * 
 * Each node has an actual size, and an allocated size (alligned). The
 * NV backed byte array (s_NV) is iterated through to find each node.
 * 
 * A variable's data may be spread across multiple nodes via a linked
 * list. This list is represented via relative offset values in each node.
 * 
 * For each node:
 *      - Previous runs of the memory reclamation code may have removed
 *          a variable which broke another variable into multiple node.
 *          Merge these adjacent node into a single large node.
 *      - Is the space used by the current node smaller than the 
 *          allocated space (not less than min alignment)?
 *      - Or has the variable been deleted?
 *      - If yes to either then find the next variable, skipping over
 *          deleted variables along the way.
 *      - Move the next (non-deleted) node forward into the free space.
 *      - Increase the allocation size of that node so there is no
 *          gap left. When the node is processed that gap will be
 *          closed.
 *      - If the current node has a NextOffset link to another node
 *          in the list:
 *              - Keep track of the current node so its offset can be
 *                  updated if the next node is moved forwards.
 *      - Check the list of tracked node to see if any were linked
 *          to the next node (which we may have just moved into reclaimed space),
 *          if so update the link and remove them from the list since 
 *          the next block has reached it's final location.
 */

CHAR*
CovnertWCharToChar( WCHAR *Unicode, CHAR *Ascii, UINT32 AsciiBufferLength) {
    CHAR *returnPtr = Ascii;
    while(Unicode != L'\0' && AsciiBufferLength > 1) {
        if (*Unicode <= 0x7F) {
            *Ascii = (CHAR) *Unicode;
        } else {
            *Ascii = '#';
        }
        Ascii++;
        Unicode ++;
        AsciiBufferLength--;
    }
    *Ascii = '\0';
    return returnPtr;
}

#if (TRACE_LEVEL < TRACE_DEBUG)
#define DumpAuthvarMemory()   (void)0
#else
#define DumpAuthvarMemory()   DumpAuthvarMemoryImpl()


VOID
DumpAuthvarMemoryImpl(VOID)
{
    PUEFI_VARIABLE pVar = (PUEFI_VARIABLE)ROUNDUP((UINT_PTR)&(s_NV[NV_AUTHVAR_START]), NV_AUTHVAR_ALIGNMENT);
    PUEFI_VARIABLE pLinkVar;
    const UINT32 maxNameLength = 50;
    CHAR convertedName[maxNameLength];

    UINT32 mainCounter = 0, linkCounter;
    BOOL isLinkedTo[NV_AUTHVAR_SIZE / sizeof(UEFI_VARIABLE)] = {0};

    FMSG("================================");
    FMSG("Start of Authvar Memory at  0x%lx:", (UINT_PTR)s_NV);
    FMSG("");
    FMSG("#Num:                              |Offset( Address ) | Alloc( Data Size) | State | Link To | <--->");
    while (((UINT_PTR)pVar - (UINT_PTR)s_NV) < s_nextFree) {
        
        if (pVar->AllocSize == 0) {
            FMSG("ERROR! Memory is bad!");
            break;
        }

        mainCounter++;
        linkCounter = 0;
        if (pVar->NextOffset) {
            pLinkVar = pVar;
            linkCounter = mainCounter;
            // Run through the list until we find our linked node, keeping track of numbering on the way
            // Note: pVar->BaseAddress may not have been updated yet, use actual address.
            while((UINT_PTR)pLinkVar != (UINT_PTR)pVar + pVar->NextOffset) {
                linkCounter++;
                pLinkVar = (PUEFI_VARIABLE)((UINT_PTR)pLinkVar + pLinkVar->AllocSize);
            }
            isLinkedTo[linkCounter] = true;
        }

        const char *name = pVar->NameOffset ? 
                        name = CovnertWCharToChar((WCHAR *)((UINT_PTR)pVar + (UINT_PTR)pVar->NameOffset),
                                convertedName, maxNameLength)
                        : "";

        UINT_PTR offset = pVar->BaseAddress - (UINT_PTR)s_NV;
        //Check if variable has been deleted
        const PCCH type = (memcmp(&(pVar->VendorGuid), &GUID_NULL, sizeof(GUID)) ?  "   " : "DEL");
        //Check if its a link variable
        const PCCH linkIn = (isLinkedTo[mainCounter] ? "<-" : "");
        const PCCH linkMiddle = (isLinkedTo[mainCounter] || pVar->NextOffset ? "--" : "");
        const PCCH linkOut = (pVar->NextOffset ? "->" : "");

        FMSG("#%3d:%-30s|%#7lx(%#9lx)| A:%#6x(D:%#6x) | %s | Next:%-2d | %s%s%s",
                mainCounter, name, offset, (UINT_PTR)pVar, pVar->AllocSize, pVar->DataSize, type,
                linkCounter, linkIn, linkMiddle, linkOut);
        //DMSG("%s-0x%x(+0x%lx):    (#%d:%s,Link:%d)", linked, pVar->AllocSize, (UINT_PTR)pVar, mainCounter, type, linkCounter);
        pVar = (PUEFI_VARIABLE)((UINT_PTR)pVar + pVar->AllocSize);
    }
    FMSG("End of authvar memory at 0x%lx: (Max:0x%lx)", (UINT_PTR)&(s_NV[s_nextFree]), (UINT_PTR)&(s_NV[s_nvLimit]));
    FMSG("================================");

    // If we run too fast, the serial print can't keep up
    // OP-TEE uses very aggresive optimization, need to work
    // to trick it.
    volatile uint32_t counter0, counter1;
    static volatile uint32_t collector = 1;
    for(counter0 = 1; counter0 < 500; counter0++) {
        for (counter1 = 1; counter1 < 100000; counter1++) {
            collector = (collector + 1) * mainCounter;
        }
    }
    FMSG("%d", collector);
}
#endif

VOID
UpdateOffsets(
    UINT_PTR NVOffset,
    UINT32 ShrinkAmount
)
/*++

    Routeine Description:

        Updates any nodes which point to NVOffset bytes into s_NV such that it will now
        point to (NVOffset - ShrinkAmount).

        Stops tracking any nodes which will no longer be affected by subsequent
        changes to the layout.

    Arguments:

        NVOffset - Offset into s_NV of the old location of the node which has been moved
        
        ShrinkAmount - How much the stored node was moved forward in memory
--*/
{
    PLIST_ENTRY head = &MemoryReclamationList;
    PLIST_ENTRY cur = head->Flink;
    PMEMORY_RECLAMATION_NODE node;

    FMSG("Updating nodes which point to 0x%lx (0x%lx), shrink:0x%x)", NVOffset, NVOffset + (UINT_PTR)s_NV, ShrinkAmount);
    // Check each tracked block and update it if its nextOffset value
    // is no longer correct.
    while ((cur) && (cur != head)) {
        node = (PMEMORY_RECLAMATION_NODE)cur;
        if(node->NV_Offset == NVOffset) {
            // No longer need to track this node
            FMSG("Done with the node at 0x%lx", (UINT_PTR)node->VariableNode);
            FMSG("(0x%lx -> 0x%lx)", node->NV_Offset + (UINT_PTR)s_NV, node->NV_Offset - ShrinkAmount + (UINT_PTR)s_NV);
            node->VariableNode->NextOffset -= ShrinkAmount;
            RemoveEntryList(cur);
            cur = cur->Flink;
            TEE_Free(node);

            // Nodes will only have one parent, no need to look for more.
            break;
        } else {
            cur = cur->Flink;
        }
    }
}

VOID
TrackOffset(
    PUEFI_VARIABLE Node
)
/*++

    Routine Description:

        Track this node so any changes to the memory
        layout may be reflected in its NextOffset value.

    Arguments:

        Node - Variable node to track

--*/
{
    PMEMORY_RECLAMATION_NODE newReclamationNode = TEE_Malloc(sizeof(MEMORY_RECLAMATION_NODE),
                                                    TEE_USER_MEM_HINT_NO_FILL_ZERO);
    if (!newReclamationNode) {
        EMSG("Out of memory during initialization, fatal error");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
    }

    newReclamationNode->VariableNode = Node;
    newReclamationNode->NV_Offset = (UINT_PTR)Node + Node->NextOffset - (UINT_PTR)s_NV;
    InsertTailList(&MemoryReclamationList, &(newReclamationNode->List));
    FMSG("Tracking a variable which points to 0x%lx", newReclamationNode->NV_Offset + (UINT_PTR)s_NV);
}

VOID
MergeAdjacentNodes (PUEFI_VARIABLE FirstNode)
/*++
    Routine Description:

        Merge any adjacent nodes of the same variable together.
        This may occur when another variable was deleted in between
        the linked nodes.

        The first node is expanded to include the next adjacent node's
        allocated space, and the next offset is updated. The data from
        the adjacent node is then added to the first. All subsequent
        nodes, if they are also adjacent to the new expanded node, are
        also merged.

    Arguments:

        FirstNode - Pointer to a node of a variable which should be
            merged with any adjacent nodes of the same variable if, 
            they exist. This node does not need to be the head of the list.
--*/
{
    PUEFI_VARIABLE adjacentNode;
    UINT32 sourceOffset, destinationOffset, moveSize;

    FMSG("Looking to merge node at 0x%lx with adjacent nodes", (UINT_PTR)FirstNode);

    while (FirstNode->NextOffset != 0 && 
            FirstNode->NextOffset == FirstNode->AllocSize) {
        adjacentNode = (PUEFI_VARIABLE)(FirstNode->BaseAddress + FirstNode->NextOffset);
        FMSG("Variable has an adjacent node at 0x%lx", (UINT_PTR)FirstNode);

        if ((UINT_PTR)(adjacentNode + adjacentNode->AllocSize) >= (UINT_PTR)&(s_NV[s_nvLimit]))
        {
            // Sign of corruption, we don't want to add unknown data to a variable.
            TEE_Panic(TEE_ERROR_BAD_STATE);
        }

        if (adjacentNode->NextOffset != 0)
        {
            FirstNode->NextOffset = adjacentNode->NextOffset + FirstNode->AllocSize;
        } else {
            FirstNode->NextOffset = 0;
        }
        FMSG("Merged block will have next offset 0x%lx", adjacentNode->NextOffset + FirstNode->AllocSize);
        FirstNode->AllocSize += adjacentNode->AllocSize;
        FMSG("Merged block will have allocation size 0x%x", FirstNode->AllocSize);
        moveSize = adjacentNode->DataSize;
        FMSG("Merged block will have data size (0x%x+0x%x) = 0x%x", 
                FirstNode->DataSize, 
                adjacentNode->DataSize, 
                FirstNode->DataSize + adjacentNode->DataSize);

        sourceOffset = (adjacentNode->BaseAddress + adjacentNode->DataOffset) - (UINT_PTR)s_NV;
        destinationOffset = (FirstNode->BaseAddress + FirstNode->DataOffset + FirstNode->DataSize) - (UINT_PTR)s_NV;
        FMSG("Moving 0x%x bytes of data from 0x%lx to 0x%lx", 
                moveSize,
                (adjacentNode->BaseAddress + adjacentNode->DataOffset),
                (FirstNode->BaseAddress + FirstNode->DataOffset + FirstNode->DataSize));
        _plat__NvMemoryMove(sourceOffset, destinationOffset, moveSize);
        
        FirstNode->DataSize += moveSize;
        _plat__MarkDirtyBlocks(adjacentNode->BaseAddress - (UINT_PTR)s_NV, sizeof(UEFI_VARIABLE));
    }
}

BOOLEAN
ReclaimNode(
    PUEFI_VARIABLE Node
)
/*++

    Routine Description:

        Memory reclamation for AuthVar storage. Shrinks or
        removes a variable node if it has been deleted or had its
        data reduced. Moves the next node in memory to remove
        gaps while increasing its allocated size. A subsequent call
        to ReclaimNode on that node will similarrly attempt
        to reclaim the wasted space.

        Maintains a list of nodes which may need to have their offsets
        updated and will udpate them as needed. This function guarantees
        that s_NV will allways be internally consistent before and 
        after calling.

    Arguments:

        Node - Pointer to the variable to shrink/remove

    Returns:

        TRUE - Node was deleted

        FALSE - Node was left in place (but possibly shrunk)
--*/
{
    UINT32 newNodeSize, wastedSpace, newAlloc, shrinkAmmount, 
            deleteAmmount, nextNodeOldAllocSize;
    PUEFI_VARIABLE nextNode;
    BOOLEAN wasDeleted = FALSE;

    FMSG("Reclaiming memory at 0x%lx", (UINT_PTR)Node);

    // If s_nextFree is not consistent with actual data, we will run into
    // an all zero block. This is a sign of data corruption and is 
    // considered an error.
    if (Node->AllocSize == 0) {
        EMSG("Detected corruption in authenticated variable store");
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }

    // Check if the variable has been deleted
    if(!memcmp(&(Node->VendorGuid), &GUID_NULL, sizeof(GUID))) {
        DMSG("Cleaning up deleted variable at 0x%lx", (UINT_PTR)Node);
        newNodeSize = 0;
        wasDeleted = TRUE;
    } else {
        // If possible, merge adjacent blocks which are fragmented.
        MergeAdjacentNodes(Node);

        // If this variable still has multiple blocks it may be necessary to update
        // the offsets as memory is reclaimed.
        if (Node->NextOffset) {
            TrackOffset(Node);
        }

        newNodeSize = Node->DataOffset + Node->DataSize;
    }

    wastedSpace = pVar->AllocSize - newVariableSize;
    DMSG("Total size is 0x%x, Wasted space is 0x%x", newVariableSize, wastedSpace);

    // We need to remain alligned, don't reclaim gaps smaller
    // than our alignment.
    if (wastedSpace < NV_AUTHVAR_ALIGNMENT) {
        FMSG("Can't reclaim less than 0x%x", NV_AUTHVAR_ALIGNMENT);
        //
        // If we aren't moving the next variable, we don't need to track
        // offsets to it anymore.
        //
        UpdateOffsets((UINT_PTR)Node + Node->AllocSize - (UINT_PTR)s_NV, 0);
        return 0;
    }

    newAlloc = ROUNDUP(newNodeSize, NV_AUTHVAR_ALIGNMENT);
    shrinkAmmount = Node->AllocSize - newAlloc;

    FMSG("We actually need 0x%x, 0x%x less than before", newAlloc, shrinkAmmount);

    // Search ahead for the first non-deleted variable, or the end of memory
    // We may as well colapse multiple variables in one go.
    // If our memory becomes corrupt the next variable may have alloc size 0.
    // This will be caught on the next iteration of ReclaimNode().
    nextNode = (PUEFI_VARIABLE)(Node->BaseAddress + Node->AllocSize);
    deleteAmmount = 0;
    while (((UINT_PTR)nextNode - (UINT_PTR)s_NV < s_nextFree) &&
            !memcmp(&(nextNode->VendorGuid), &GUID_NULL, sizeof(GUID)) &&
            nextNode->AllocSize > 0) {

        FMSG("Found deleted variable of size 0x%x at 0x%lx", nextNode->AllocSize, 
            (UINT_PTR)nextNode);
        deleteAmmount += nextNode->AllocSize;
        // nextNode's BaseAddress has not been updated yet, use actual address.
        nextNode = (PUEFI_VARIABLE)((UINT_PTR)nextNode + nextNode->AllocSize);
    }

    FMSG("Total wasted space: 0x%x", shrinkAmmount + deleteAmmount);
    Node->AllocSize -= shrinkAmmount;

    // No need to move data at the end of storage, just colapse the end pointer
    if((UINT_PTR)nextNode - (UINT_PTR)s_NV >= s_nextFree) {
        FMSG("Last variable, shrinking s_nextFree");
        s_nextFree -= (shrinkAmmount + deleteAmmount);
        FMSG("s_nextFree is now 0x%lx (0x%lx)", s_nextFree, (UINT_PTR)&s_NV[s_nextFree]);
        // It is important to clear data from the end of the list. This allows us to detect
        // corruption (ie s_nextFree points past the end of actual data due to a power failure
        // during write back).
        _plat__NvMemoryClear(s_nextFree, shrinkAmmount + deleteAmmount);
        
        PLIST_ENTRY head = &MemoryReclamationList;
        PLIST_ENTRY cur = head->Flink;
        if(head != cur) {
            EMSG("Reclemation list is broken, was expecting to update pointers to 0x%lx",
                ((PMEMORY_RECLAMATION_NODE)head->Flink)->NV_Offset);
            TEE_Panic(TEE_ERROR_BAD_STATE);
        }
    } else {
        // Move the next variable into the extra space, then
        // expand that variable so it is allocated the entire gap.
        // This space will be reclaimed in the next call to ReclaimNode().
        // If s_nextFree is not consistent with actual data, we will run into an all zero block.
        // This is a sign of data corruption and is considered an irrecoverable error.
        if (nextNode->AllocSize == 0) {
            EMSG("Detected corruption in authenticated variable store");
            TEE_Panic(TEE_ERROR_BAD_STATE);
        }

        nextNodeOldAllocSize = nextNode->AllocSize;

        nextNode->AllocSize += shrinkAmmount + deleteAmmount;
        FMSG("Next node now has alloc size of 0x%x", nextNode->AllocSize);

        // Keeping the internal structure up to date is required to allow
        // printing of the current memory state.
        if(nextNode->NextOffset) {
            nextNode->NextOffset += shrinkAmmount + deleteAmmount;
        }

        FMSG("Moving node at 0x%lx to 0x%lx (size=0x%x)", (UINT_PTR)nextNode,
            Node->BaseAddress + Node->AllocSize, nextNodeOldAllocSize);
        _plat__NvMemoryMove((UINT_PTR)nextNode - (UINT_PTR)s_NV,
            Node->BaseAddress + Node->AllocSize - (UINT_PTR)s_NV,
            nextNodeOldAllocSize);

        // Update any links which pointed to nextNode, which has been moved to colapse
        // a gap
        UpdateOffsets((UINT_PTR)nextNode - (UINT_PTR)s_NV, shrinkAmmount + deleteAmmount);
    }

    return wasDeleted;
}

UINT32
AuthVarInitStorage(
    UINT_PTR StartingOffset,
    BOOLEAN ReInitialize
)
/*++

    Routine Description:

        AuthVar storage initializaion routine

    Arguments:

        StartingOffset - Offset from 0 of first byte of AuthVar NV storage

        ReInitialize - Are we re-initializing memory at run-time? This can be done
            to try and clear up deleted variables.

    Returns:

        0 - Failure

        1 - Success

--*/
{
    NV_AUTHVAR_STATE authVarState;
    PUEFI_VARIABLE currentNode;
    PCWSTR name;
    PCGUID guid;
    VARTYPE varType;
    VARTYPE i;

    // Sanity check on storage offset unless we are explicitly re-initializing
    // the memory.
    if (!ReInitialize && (StartingOffset != s_nextFree))
    {
        // REVISIT: TEE_Panic()?
        return 0;
    }

    // At this point we have read all of NV from storage and we are now in
    // TA_CreateEntryPoint. We now need to traverse our in-memory NV (s_NV)
    // and add pointers to each UEFI_VARIABLE (that isn't just a container for
    // appended data) to the appropriate in-memory variable list.

    // Also note that the links (flink/blink) in the variable entries in NV
    // may be non-zero. These values are garbage and are ignored. They will
    // be set appropriately when added to the in-memory list(s).

    // Get our Admin state and sanity check ending offset
    _admin__RestoreAuthVarState(&authVarState);
    s_nextFree = authVarState.NvEnd;
    IMSG("Initializing authenticated variable store");
    FMSG("nextFree/NvEnd:0x%lx, s_nvLimit:0x%lx (size:%lx)", (UINT_PTR)authVarState.NvEnd, s_nvLimit, NV_AUTHVAR_SIZE);
    FMSG("s_NV enforced alignment is 0x%x bytes", NV_AUTHVAR_ALIGNMENT);
    if (!(s_nextFree < s_nvLimit))
    {
        EMSG("FAILED: Inconsistent nextFree/NvEnd.");
        return TEE_ERROR_BAD_STATE;
    }

    // Init in-memory lists
    for (i = 0; i < VTYPE_END; i++) {
        if (ReInitialize && i == VTYPE_VOLATILE) {
            // The lists which track NV need to be rebuilt anyways, but
            // the volatile variables need to be kept track of.
            continue;
        }
        InitializeListHead(&(VarInfo[i].Head));
    }
    
    // Is our storage empty (i.e., we have no saved vars)?
    if (s_nextFree == StartingOffset) {
        DMSG("First run, storage initialized.");

        // All we're doing here right now is saving our end-offset, as we
        // get more sophisticated in AuthVars, this is where we would write
        // any other initial AuthVar state.
        authVarState.NvEnd = s_nextFree;
        _admin__SaveAuthVarState(&authVarState);
        return 1;
    }

    DumpAuthvarMemory();
    InitializeListHead(&MemoryReclamationList);
    
    // Init ptr to start of AuthVar storage
    if(ROUNDUP((UINT_PTR)&s_NV[s_nextFree], NV_AUTHVAR_ALIGNMENT) !=
        (UINT_PTR)&s_NV[s_nextFree] ) {
            EMSG("Alignment error! 0x%lx, 0x%lx",
                ROUNDUP((UINT_PTR)&s_NV[s_nextFree], NV_AUTHVAR_ALIGNMENT),
                (UINT_PTR)&s_NV[s_nextFree] );
            TEE_Panic(TEE_ERROR_BAD_STATE);
    }
    currentNode = (PUEFI_VARIABLE)ROUNDUP((UINT_PTR)s_NV + StartingOffset, NV_AUTHVAR_ALIGNMENT);

    do {
        // Init before gettype
        currentNode->BaseAddress = (UINT_PTR)currentNode;
        guid = (PCGUID)&(currentNode->VendorGuid);
        name = (PCWSTR)(currentNode->BaseAddress + currentNode->NameOffset);

        // Check if deleted or appended data entry
        FMSG("Checking state of Node at 0x%lx", (UINT_PTR)currentNode);
        if (GetVariableType(name, guid, currentNode->Attributes, &varType))
        {
            // Only track a node if it is the first entry
            if(currentNode->NameSize > 0)
            {
                // Add pointer to this var to appropriate in-memory list
                FMSG("Adding variable to lists");
                InsertTailList(&VarInfo[varType].Head, &currentNode->List);
            }
        }

        // Attempt to reclaim unused memory from the current variable,
        // then compute pointer to next var. If the current variable was
        // deleted then the next variable will have been moved to the
        // same location.
        if (!ReclaimNode(currentNode)) {
            // Variable was not deleted, move to the next variable
            currentNode = (PUEFI_VARIABLE)(currentNode->BaseAddress + currentNode->AllocSize);
        }

        DumpAuthvarMemory();
    } while (((UINT_PTR)currentNode - (UINT_PTR)s_NV) < s_nextFree);

    authVarState.NvEnd = s_nextFree;
    _admin__SaveAuthVarState(&authVarState);

    DMSG("Authvar memory initialized");

    // No need to commit NV changes to disk now, wait until data has been modified.
    return 1;
}

VOID
CompressAuthvarMemory(
    VOID
)
/*++

    Routine Description:

        Re-initializes the NV memory in an attempt to find wasted space.

--*/
{
    FMSG("Optimizing memory, currently 0x%lx free", s_nvLimit - s_nextFree);
    if(!AuthVarInitStorage(NV_AUTHVAR_START, TRUE)) {
        EMSG("Failed to re-initialize NV memory");
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }
    FMSG("Optimizing done, now 0x%lx free", s_nvLimit - s_nextFree);
}

//
// Auth Var Mgmt Functions
//

VOID
SearchList(
    PCUNICODE_STRING     UnicodeName,   // IN
    PCGUID               VendorGuid,    // IN
    PUEFI_VARIABLE      *Var,           // OUT
    VARTYPE             *VarType        // OUT
)
/*++

    Routine Description:

        Search the global in-memory list to check if Var has already been set (written).
        Var may be volatile or non-volatile.

    Arguments:

        UnicodeName - Name of the variable being searched

        VendorGuid - GUID of the variable

        Var - Pointer to the variable's first node. NULL if not found.

        VarType - Type used to determine variable's info and storage

    Returns:

    None

    --*/
{
    UINT32 i;

    FMSG("Searching lists for variable");

    // Validate parameters
    if (!(UnicodeName) || !(VendorGuid) || !(Var) || !(VarType))
    {
        DMSG("Invalid search parameters");
        return;
    }

    *Var = NULL;

    // Run the list(s)
    for (i = 0; i < ARRAY_SIZE(VarInfo) && *Var == NULL; i++)
    {
        PLIST_ENTRY head = &VarInfo[i].Head;
        PLIST_ENTRY cur = head->Flink;

        while ((cur) && (cur != head))
        {
            if (CompareEntries(UnicodeName, VendorGuid, (PUEFI_VARIABLE)cur))
            {
                *Var = (PUEFI_VARIABLE)cur;
                *VarType = VarInfo[i].Type;
                break;
            }

            cur = cur->Flink;
        }
    }

    return;
}

TEE_Result
CreateVariable(
    PCUNICODE_STRING        UnicodeName,
    PCGUID                  VendorGuid,
    ATTRIBUTES              Attributes,
    PEXTENDED_ATTRIBUTES    ExtAttributes,
    UINT32                  DataSize,
    PBYTE                   Data
)
/*++

    Routine Description:

        Function to create a variable

    Arguments:

        UnicodeName - Name of the variable being created

        VendorGuid - GUID of the variable

        Attibutes - UEFI variable attributes

        DataSize - Size in bytes of Data

        Data - pointer to the data

    Returns:
    
        TEE_Result

--*/
{
    PUEFI_VARIABLE newVar = NULL;
    PWSTR newStr = NULL;
    PBYTE newData = NULL;
    PEXTENDED_ATTRIBUTES newExt = NULL;
    UINT32 totalNv = 0, strLen = 0, extAttribLen = 0;
    VARTYPE varType;
    NV_AUTHVAR_STATE authVarState;
    TEE_Result status = TEE_SUCCESS;

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        DMSG("Creating volatile variable");
        // Validate length
        if (DataSize == 0)
        {
            // TODO: I believe there are circumstances under which it is permitted
            //       to create a var with zero DataSize. But I guess we'll cross 
            //       that bridge when we come to it.
            status = TEE_ERROR_BAD_PARAMETERS;
            EMSG("Create volatile variable error: Bad parameters.");
            goto Cleanup;
        }

        // Attempt allocation for variable
        if (!(newVar = TEE_Malloc(sizeof(UEFI_VARIABLE), TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            EMSG("Create volatile variable error: Out of memory.");
            goto Cleanup;
        }

        // Attempt allocation for variable name
        if (!(newStr  = TEE_Malloc(UnicodeName->MaximumLength, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            TEE_Free(newVar);
            status = TEE_ERROR_OUT_OF_MEMORY;
            EMSG("Create volatile variable error: Out of memory.");
            goto Cleanup;
        }

        // Attempt allocation for variable data
        if (!(newData = TEE_Malloc(DataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            TEE_Free(newVar);
            TEE_Free(newStr);
            status = TEE_ERROR_OUT_OF_MEMORY;
            EMSG("Create volatile variable error: Out of memory.");
            goto Cleanup;
        }

        // Init volatile variable storage
        memset(newVar, 0, sizeof(UEFI_VARIABLE));

        // Guid/Attributes
        newVar->VendorGuid = *VendorGuid;
        newVar->Attributes.Flags = Attributes.Flags;

        // Pointers to name, etc. are proper memory addresses, not
        // offsets inside the memory map
        newVar->BaseAddress = 0;

        // Init/copy variable name
        newVar->NameSize = UnicodeName->MaximumLength;
        newVar->NameOffset = (UINT_PTR)newStr;
        memmove(newStr, UnicodeName->Buffer, newVar->NameSize);

        // Init/copy variable data
        newVar->DataSize = DataSize;
        newVar->DataOffset = (UINT_PTR)newData;
        memmove(newData, Data, DataSize);

        // Note the lack of a check against ExtendedAttributes.
        // We do not implement authenticated volatile variables.

        // Add it to the list
        InsertTailList(&(VarInfo[VTYPE_VOLATILE].Head), &newVar->List);

        // Success
        status = TEE_SUCCESS;
        FMSG("Created volatile variable");
        goto Cleanup;
    }
    else
    {
        // Nope, create new non-volatile variable.
        DMSG("Creating non-volatile variable");
        // Which list is this variable destined for?
        if (!GetVariableType(UnicodeName->Buffer, VendorGuid, Attributes, &varType))
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            EMSG("Create non-volatile variable error: Bad parameters.");
            goto Cleanup;
        }

        // Get strlen of unicode name
        strLen = UnicodeName->MaximumLength;

        // Get size if extended attributes (if provided)
        if (ExtAttributes)
        {
            extAttribLen = sizeof(EXTENDED_ATTRIBUTES) + ExtAttributes->PublicKey.Size;
        }
        else
        {
            extAttribLen = 0;
        }

        // Total NV requirement to store this var
        totalNv = sizeof(UEFI_VARIABLE) + strLen + DataSize + extAttribLen;

        FMSG("Storing 0x%x bytes (variable + name + data)", totalNv);

        DMSG("t: %x snF: %lx nvLim: %lx", totalNv, s_nextFree, s_nvLimit);
        // Is there enough room on this list and in NV?
        if ((totalNv + s_nextFree) > s_nvLimit)
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Need to create a new structure to hold the data.
        // To satisfy the compiler that allignment is fine use
        // ROUNDUP.
        if(ROUNDUP((UINT_PTR)&s_NV[s_nextFree], NV_AUTHVAR_ALIGNMENT) !=
            (UINT_PTR)&s_NV[s_nextFree] ) {
                DMSG("Alignment error! 0x%lx, 0x%lx",
                    ROUNDUP((UINT_PTR)&s_NV[s_nextFree], NV_AUTHVAR_ALIGNMENT),
                    (UINT_PTR)&s_NV[s_nextFree] );
                TEE_Panic(TEE_ERROR_BAD_STATE);
        }
        newVar = (PUEFI_VARIABLE)ROUNDUP((UINT_PTR)&s_NV[s_nextFree], NV_AUTHVAR_ALIGNMENT);

        // Init pointers to new fields

        FMSG("newVar: 0x%lx", (UINT_PTR)newVar);
        newVar->BaseAddress = (UINT_PTR)newVar;
        newStr = (PWSTR)((UINT_PTR)newVar + sizeof(UEFI_VARIABLE));
        FMSG("New string is at 0x%lx, with length 0x%x", (UINT_PTR)newStr, strLen);
        newExt = (PEXTENDED_ATTRIBUTES)((UINT_PTR)newStr + strLen);
        FMSG("New ext is at 0x%lx, with length 0x%x", (UINT_PTR)newExt, extAttribLen);
        newData = (PBYTE)((UINT_PTR)newExt + extAttribLen);
        FMSG("New data is at 0x%lx, with length 0x%x", (UINT_PTR)newData, DataSize);

        // Init variable structure
        newVar->VendorGuid = *VendorGuid;
        newVar->Attributes.Flags = Attributes.Flags;
        newVar->NameSize = strLen;
        newVar->NameOffset = (UINT_PTR)newStr - newVar->BaseAddress;

        // Copy name and data
        memmove(newStr, UnicodeName->Buffer, strLen);

        // Size of var structure before any appended data that may come later
        // Make sure all structures are aligned properly.
        newVar->AllocSize = ROUNDUP(totalNv, NV_AUTHVAR_ALIGNMENT);
        // Extended attributes, if necessary
        if (!extAttribLen)
        {
            // No extended attributes
            newVar->ExtAttribSize = 0;
            newVar->ExtAttribOffset = 0;
        }
        else
        {
            // Copy extended attributes
            newVar->ExtAttribSize = extAttribLen;
            newVar->ExtAttribOffset = (UINT_PTR)newExt - newVar->BaseAddress;
            memmove(newExt, ExtAttributes, extAttribLen);
        }

        // Data fields
        newVar->DataSize = DataSize;
        newVar->DataOffset = (UINT_PTR)newData - newVar->BaseAddress;
        memmove(newData, Data, DataSize);

        // Creating this var we don't yet have appended data
        newVar->NextOffset = 0;

        // We've touched NV so, mark for write back.
        _plat__MarkDirtyBlocks(newVar->BaseAddress - (UINT_PTR)s_NV, newVar->AllocSize);

        FMSG("Updating s_nextFree from 0x%lx -> 0x%lx by incrementing %x ",
            (UINT_PTR)s_NV + s_nextFree, 
            (UINT_PTR)s_NV + s_nextFree + newVar->AllocSize,
            newVar->AllocSize);

        // Update offset to next free byte. Alloc size is already rounded up to maintain
        // proper alignment.
        s_nextFree += newVar->AllocSize;
        authVarState.NvEnd = s_nextFree;
        _admin__SaveAuthVarState(&authVarState);

        // Update the in-memory list
        InsertTailList(&VarInfo[varType].Head, &newVar->List);
        FMSG("Created non-volatile variable");
    }
Cleanup:
    DumpAuthvarMemory();
    return status;
}

TEE_Result
RetrieveVariable(
    PUEFI_VARIABLE       Var,           // IN
    VARIABLE_GET_RESULT *ResultBuf,     // OUT
    UINT32               ResultBufLen,  // IN
    UINT32              *BytesWritten   // OUT (optional)
)
/*++

    Routine Description:

        Function for getting (reading) a variable's data.

    Arguments:

        Var - Pointer to the variable's entry in memory.

        ResultBuf - Buffer to hold result (attributes, datasize, and data)

        ResultBufLen - Size of ResultBuffer

        BytesWritten - total bytes copied into (or needed for) ResultBuf

    Returns:

        TEE_Result

--*/
{
    PBYTE dstPtr, limit;
    UINT_PTR nextOffset;
    PUEFI_VARIABLE currentNode;
    UINT32 requiredSize, length;
    TEE_Result status = TEE_SUCCESS;

    DMSG("Getting data from variable at 0x%lx", (UINT_PTR)Var);

    // Detect integer overflow
    if (((UINT32)ResultBuf + ResultBufLen) < (UINT32)ResultBuf)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    //Calculate the total size required
    currentNode = Var;
    requiredSize = 0;
    do {
        FMSG("Adding size 0x%x", currentNode->DataSize);
        requiredSize += currentNode->DataSize;
        nextOffset = currentNode->NextOffset;
        currentNode = (PUEFI_VARIABLE)(currentNode->BaseAddress + nextOffset);
    } while ((nextOffset));
    FMSG("Total required size is 0x%x", requiredSize);

    FMSG("ResultBufLen:0x%x, we want to store 0x%x", ResultBufLen, (requiredSize + sizeof(VARIABLE_GET_RESULT)));
    ResultBuf->DataSize = requiredSize;

    if (ResultBufLen < (requiredSize + sizeof(VARIABLE_GET_RESULT)))
    {
        // This is a common error case, a buffer size of 0 is often passed
        // to check the required size.
        DMSG("Retreive variable error: result buffer too short.");
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

    // Copy variable data
    ResultBuf->Attributes = Var->Attributes.Flags;
    ResultBuf->Size = sizeof(VARIABLE_GET_RESULT) + ResultBuf->DataSize;

    // Init for copy
    dstPtr = ResultBuf->Data;
    limit = dstPtr + ResultBufLen;

    // Do the copy (accross appended data entries if necessary)
    currentNode = Var;
    do {
        // Calculate length and copy data
        length = currentNode->DataSize;

        FMSG("Copying 0x%x bytes from 0x%lx to 0x%p", length, (UINT_PTR)(currentNode->DataOffset + currentNode->BaseAddress), dstPtr);
        memcpy(dstPtr, (PBYTE)(currentNode->DataOffset + currentNode->BaseAddress), length);

        // Adjust destination pointer
        dstPtr += length;

        // Pickup offset to next set of appended data (may be zero)
        nextOffset = currentNode->NextOffset;

        // Calculate pointer to next set of appended data
        currentNode = (PUEFI_VARIABLE)(currentNode->BaseAddress + nextOffset);

        // Loop if we have another entry and we haven't written size bytes yet
    } while ((nextOffset != 0) && (dstPtr < limit));

Cleanup:
    if (BytesWritten) // or needed..
    {
        *BytesWritten = requiredSize + sizeof(VARIABLE_GET_RESULT);
        DMSG("Required buffer size is 0x%x bytes", *BytesWritten);
    }

    return status;
}

TEE_Result
DeleteNode(
    PUEFI_VARIABLE  Tail
)
/*++

    Routine Description:

        Marks the tail of a list of nodes as deleted. If called on the
        first node of a variable the entire varaible will be deleted, 
        otherwise the variable is truncated.

        It is the caller's responsibility to clean up any links to the
        deleted nodes when truncating.

        The node can be either volatile or non-volatile.

    Arguments:

        Tail - Pointer to the nodes's location in memory.

    Returns:

        TEE_Result

--*/
{
    UINT_PTR NextOffset;

    DMSG("Deleting variable at 0x%lx", (UINT_PTR)Tail);

    // First, is this a volatile variable?
    if (!(Tail->Attributes.NonVolatile))
    {
        FMSG("Volatile delete");
        TEE_Free((PBYTE)Tail->DataOffset);
        TEE_Free((PBYTE)Tail->NameOffset);
        TEE_Free((PBYTE)Tail);
    } else {
        FMSG("Non-volatile delete");
        do {
            FMSG("Clearing GUID and attributes from 0x%lx", (UINT_PTR)Tail);
            _plat__NvMemoryWrite((UINT_PTR)&(Tail->VendorGuid) - (UINT_PTR)s_NV, sizeof(GUID), &GUID_NULL);
            _plat__NvMemoryClear((UINT_PTR)&(Tail->Attributes.Flags) - (UINT_PTR)s_NV, sizeof(Tail->Attributes.Flags));

            NextOffset = Tail->NextOffset;
            Tail = (PUEFI_VARIABLE)(Tail->BaseAddress + NextOffset);
        } while (NextOffset != 0);

    }

    DumpAuthvarMemory();
    return TEE_SUCCESS;
}

TEE_Result
AppendVariable(
    PUEFI_VARIABLE          Var,
    ATTRIBUTES              Attributes,
    PEXTENDED_ATTRIBUTES    ExtAttributes,
    PBYTE                   Data,
    UINT32                  DataSize
)
/*++

    Routine Description:

        Function for appending to an existing variable.

    Arguments:

        Var - Pointer to a variable's first node.

        Attibutes - UEFI variable attributes

        ExtAttributes - Pointer to ExtendedAttributes (auth only)

        Data - Pointer to the data

        DataSize - Size in bytes of Data

    Returns:

        TEE_Result

--*/
{
    TEE_Result  status = TEE_SUCCESS;
    DMSG("Appending to variable at 0x%lx", (UINT_PTR)Var);

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        FMSG("Volatile append");
        PBYTE dstPtr = NULL;
        UINT32 newSize = 0;

        // TODO: CHECK FOR OVERFLOW
        newSize = Var->DataSize + DataSize;

        // Attempt allocation
        if (!(dstPtr = TEE_Malloc(newSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            EMSG("Volatile append error: out of memory");
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // First, bring over existing variable data
        // NonVolatile variables always have base address of 0, no need to
        // add it.
        memmove(dstPtr, (PBYTE)Var->DataOffset, Var->DataSize);

        // Then copy appended data
        memmove(dstPtr + Var->DataSize, Data, DataSize);

        // Free up old allocation and update new size/ptr
        TEE_Free((PVOID)Var->DataOffset);
        Var->DataSize = newSize;
        Var->DataOffset = (UINT_PTR)dstPtr;

        status = TEE_SUCCESS;
        goto Cleanup;
    }
    else {
        // Nope, append to existing non-volatile variable.
        FMSG("Non volatile append");

        PUEFI_VARIABLE currentNode = NULL, newNode = NULL;
        PBYTE apndData = NULL;
        UINT32 apndSize = 0;

        // Calculate space required for additional data. (Note that 
        // we use a UEFI_VARIABLE as a container for appended data).
        apndSize = sizeof(UEFI_VARIABLE) + DataSize;
        FMSG("We need to add 0x%x bytes", apndSize);

        // Is there enough room on the list and in NV?
        if ((apndSize + s_nextFree) > s_nvLimit)
        {
            EMSG("Non-volatile append error: out of memory");
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Ensure that we have consistency in args and var info
        if (ExtAttributes && (Var->ExtAttribOffset == 0))
        {
            EMSG("Non-volatile append error: ExtAttributes mismatch");
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Find the end of the chain. currentNode will point to the end of the chain.
        currentNode = Var;
        while (currentNode->NextOffset)
        {
            currentNode = (PUEFI_VARIABLE)(currentNode->BaseAddress + currentNode->NextOffset);
        }

        FMSG("Last node of variable at 0x%lx", (UINT_PTR)currentNode);

        // This is the last variable, we can just extend the end of memory.
        if((UINT_PTR)(currentNode->BaseAddress + currentNode->AllocSize) == (UINT_PTR)&s_NV[s_nextFree]) {
            apndData = (PBYTE)(currentNode->BaseAddress + currentNode->DataOffset + currentNode->DataSize);
            FMSG("Last node in NV, adding 0x%x bytes by extending the existing variable", DataSize);
            _plat__NvMemoryWrite((UINT_PTR)apndData - (UINT_PTR)s_NV, DataSize, Data);

            // Update sizes (we know we're adding to the end of NV data)
            currentNode->DataSize += DataSize;
            currentNode->AllocSize = ROUNDUP(currentNode->DataOffset + currentNode->DataSize, NV_AUTHVAR_ALIGNMENT);
            _plat__MarkDirtyBlocks(currentNode->BaseAddress - (UINT_PTR)s_NV, sizeof(UEFI_VARIABLE));

            // No need to create additional nodes later.
            DataSize = 0;

            s_nextFree = (currentNode->BaseAddress + currentNode->AllocSize) - (UINT_PTR)s_NV;
            NV_AUTHVAR_STATE authVarState;
            authVarState.NvEnd = s_nextFree;
            _admin__SaveAuthVarState(&authVarState);
        } else {
            // Need to add a new node to the variable.
            FMSG("Adding a new node to hold appended data");
        
            // To satisfy the compiler that allignment is fine use ROUNDUP.
            if(ROUNDUP((UINT_PTR)&s_NV[s_nextFree], NV_AUTHVAR_ALIGNMENT) !=
                (UINT_PTR)&s_NV[s_nextFree] ) {
                    DMSG("Alignment error! 0x%lx, 0x%lx",
                        ROUNDUP((UINT_PTR)&s_NV[s_nextFree], NV_AUTHVAR_ALIGNMENT),
                        (UINT_PTR)&s_NV[s_nextFree] );
                    TEE_Panic(TEE_ERROR_BAD_STATE);
            }
            newNode = (PUEFI_VARIABLE)ROUNDUP((UINT_PTR)&s_NV[s_nextFree], NV_AUTHVAR_ALIGNMENT);
            FMSG("New variable at 0x%lx", (UINT_PTR)newNode);

            newNode->BaseAddress = (UINT_PTR)newNode;
            newNode->List.Flink = newNode->List.Blink = 0;
            newNode->VendorGuid = Var->VendorGuid;
            newNode->Attributes.Flags = Attributes.Flags;
            newNode->NameSize = 0;
            newNode->NameOffset = 0;
            newNode->AllocSize = ROUNDUP(sizeof(UEFI_VARIABLE) + DataSize, NV_AUTHVAR_ALIGNMENT);
            newNode->ExtAttribSize = 0;
            newNode->ExtAttribOffset = 0;
            newNode->DataSize = DataSize;
            apndData = (PBYTE)(newNode->BaseAddress + sizeof(UEFI_VARIABLE));
            newNode->DataOffset = (UINT_PTR)apndData - newNode->BaseAddress;

            // Copy data
            memmove(apndData, Data, DataSize);

            // Update extended attributes, if present
            if (ExtAttributes)
            {
                PEXTENDED_ATTRIBUTES extAttrib;
                UINT32 extAttribLen = 0;

                // Sanity check sizes
                extAttrib = (PEXTENDED_ATTRIBUTES)(Var->BaseAddress + Var->ExtAttribOffset);
                extAttribLen = sizeof(EXTENDED_ATTRIBUTES) + ExtAttributes->PublicKey.Size;
                if (extAttribLen != (sizeof(EXTENDED_ATTRIBUTES) + extAttrib->PublicKey.Size))
                {
                    EMSG("Non-volatile append error: ExtAttributes mismatch");
                    status = TEE_ERROR_BAD_PARAMETERS;
                    goto Cleanup;
                }

                // Copy new extended attribute data
                memmove(extAttrib, ExtAttributes, extAttribLen);
            }

            // Finally, link appended variable data
            currentNode->NextOffset = newNode->BaseAddress - currentNode->BaseAddress;

            // Update the NV memory
            _plat__MarkDirtyBlocks(currentNode->BaseAddress - (UINT_PTR)s_NV, sizeof(UEFI_VARIABLE));
            _plat__MarkDirtyBlocks(newNode->BaseAddress - (UINT_PTR)s_NV, newNode->AllocSize);

            s_nextFree += newNode->AllocSize;
            NV_AUTHVAR_STATE authVarState;
            authVarState.NvEnd = s_nextFree;
            _admin__SaveAuthVarState(&authVarState);
        }
    }
Cleanup:
    DumpAuthvarMemory();
    return status;
}

TEE_Result
ReplaceVariable(
    PUEFI_VARIABLE          Var,
    ATTRIBUTES              Attributes,
    PEXTENDED_ATTRIBUTES    ExtAttributes,
    PBYTE                   Data,
    UINT32                  DataSize
)
/*++

    Routine Description:

        Function for replacing value of an existing variable

    Arguments:

        Var - Pointer to a variable's first node.

        Attibutes - UEFI variable attributes

        ExtAttributes - Pointer to ExtendedAttributes (auth only)

        Data - Pointer to the data

        DataSize - Size in bytes of Data

    Returns:

        TEE_Result

--*/
{
    PBYTE srcPtr, limit;
    PUEFI_VARIABLE dstPtr, currentNode, lastUsedNode;
    UINT_PTR nextOffset;
    UINT32 length, canFit, remaining;
    TEE_Result  status = TEE_SUCCESS;

    DMSG("Replacing variable at 0x%lx", (UINT_PTR)Var);

    EXTENDED_ATTRIBUTES NullAttributes = {0};
    if (!memcmp(ExtAttributes, &NullAttributes, sizeof(EXTENDED_ATTRIBUTES))) {
        ExtAttributes = NULL;
    }

    // We don't implement authenticated volatile variables
    if (!(Attributes.NonVolatile) && ExtAttributes)
    {
        EMSG("Replace variable error: Volatile authenticated variables not supported");
        status = TEE_ERROR_NOT_IMPLEMENTED;
        goto Cleanup;
    }

    // Some parameter checking
    if (((Attributes.TimeBasedAuth) && !ExtAttributes) ||
        (!(Attributes.TimeBasedAuth) && ExtAttributes))
    {
        EMSG("Replace variable error: Bad authentication parameters");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        FMSG("Replacing volatile variable");
        // Yes. Make sure variable doesn't indicate APPEND_WRITE.
        if ((Attributes.AppendWrite))
        {
            EMSG("Replace variable error: Bad parameters");
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // We're good, can we re-use this allocation?
        if (DataSize <= Var->DataSize) {
            // Yes, skip malloc/free
            memmove((PBYTE)Var->DataOffset, Data, DataSize);
            Var->DataSize = DataSize;
            Var->Attributes.Flags = Attributes.Flags;
            goto Cleanup;
        }

        // No, attempt allocation
        if (!(dstPtr = TEE_Malloc(DataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            EMSG("Replace volatile variable error: Out of memory");
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Success, copy new entry.
        memmove(dstPtr, Data, DataSize);

        // Free old var data and update entry
        TEE_Free((PVOID)Var->DataOffset);
        Var->DataOffset = (UINT_PTR)dstPtr;
        Var->DataSize = DataSize;
        Var->Attributes.Flags = Attributes.Flags;

        status = TEE_SUCCESS;
        goto Cleanup;
    }

    // No, replace existing non-volatile variable.
    FMSG("Replacing volatile variable");

    // Calculate the amount of NV we already have for this variable
    currentNode = Var;
    canFit = 0;
    do {
        canFit += currentNode->AllocSize - currentNode->DataOffset;
        nextOffset = currentNode->NextOffset;
        currentNode = (PUEFI_VARIABLE)(currentNode->BaseAddress + nextOffset);
    } while ((nextOffset));

    if (DataSize > canFit) {
        // We are increasing our allocation, make sure a new variable will fit.
        length = DataSize - canFit;
        if ((sizeof(UEFI_VARIABLE) + length + s_nextFree) > s_nvLimit)
        {
            EMSG("Replace non-volatile variable error: Out of NV memory");
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }
    }

    // Init for copy
    srcPtr = Data;
    remaining = DataSize;
    limit = Data + DataSize;
    currentNode = Var;
    // lastUsedNode will track the last node which holds data    
    lastUsedNode = Var;

    FMSG("Want to replace with 0x%x bytes of new data", remaining);

    // Do the copy (across appended data entries if necessary).
    // Shrinking a variable can cause fragmentation, reclaiming the
    // lost memory is handled on init.
    do {
        // Determine available space to copy to in the current variable
        canFit = currentNode->AllocSize - currentNode->DataOffset;
        FMSG("WE can fit 0x%x bytes of 0x%x into the current variable at 0x%lx",
             canFit, remaining, (UINT_PTR)currentNode);
        // Length is either the size of this entry or our remaining byte count
        length = MIN(canFit, remaining);

        memmove((PBYTE)(currentNode->BaseAddress + currentNode->DataOffset), srcPtr, length);
        currentNode->DataSize = length;

        _plat__MarkDirtyBlocks(currentNode->BaseAddress - (UINT_PTR)s_NV, currentNode->AllocSize);

        // Adjust remaining and source pointer
        remaining -= length;
        srcPtr += length;

        // Pickup offset to next set of appended data (may be zero)
        nextOffset = currentNode->NextOffset;

        if(nextOffset) {
            // Calculate pointer to next set of appended data
            lastUsedNode = currentNode;
            currentNode = (PUEFI_VARIABLE)(currentNode->BaseAddress + nextOffset);
        }

        // Loop if we have another entry and we haven't written DataSize bytes yet
    } while ((nextOffset) && (srcPtr < limit));

    // This should never happen, but if we overran our buffer then panic
    if (srcPtr > limit)
    {
        status = TEE_ERROR_OVERFLOW;
        TEE_Panic(TEE_ERROR_OVERFLOW);
        goto Cleanup;
    }

    // Did we run out of space in this variable? If so, append the remaining bytes.
    if (srcPtr < limit)
    {
        FMSG("Appending a new variable to hold 0x%x bytes", remaining);
        if (nextOffset != 0) {
            TEE_Panic(TEE_ERROR_BAD_STATE);
        }

        // Append on the rest with a new node
        status = AppendVariable(Var, Attributes, ExtAttributes, srcPtr, remaining);
    }
    else
    {
        // Data copy was successful, but is some cleanup necessary?
        if (nextOffset)
        {
            // If our next offset != 0 on what should be the last data entry, it's
            // because we 'replaced' the variable data with a smaller data size.
            // Clean up the excess appended data entries now. If there is a nextOffset
            // Var will already point to the next element in the list.
            FMSG("Clearing NextOffset from 0x%p", (PBYTE)lastUsedNode);
            status = DeleteNodes(currentNode);
            lastUsedNode->NextOffset = 0;
            _plat__MarkDirtyBlocks(lastUsedNode->BaseAddress - (UINT_PTR)s_NV, lastUsedNode->AllocSize);
        }
    }

Cleanup:
    DumpAuthvarMemory();
    return status;
}

VOID
QueryByAttribute(
    ATTRIBUTES  Attributes,             // IN
    PUINT64     MaxVarStorage,          // OUT
    PUINT64     RemainingVarStorage,    // OUT
    PUINT64     MaxVarSize              // OUT
)
/*++

    Routine Description:

        Calculates storage space information for the given attributes

    Arguments:

        Attributes - UEFI variable attributes

        MaxVarStorage - Size of storage for EFI variables associted with specified attributes

        RemainingVarStorage - Storage remaining for EFI variables associted with specified attributes

        MaxVarSize - Maximum size of an individual variable with specified attributes

    Returns:

        VOID

--*/
{   
    VARTYPE   varType;
    PUEFI_VARIABLE pVar;
    UINT64 MaxSize = 0;
    UINT32 VarSize = 0;

    DMSG("Querying variables by attributes");

    // Note that since we are not provided a (name,guid) for a query, we
    // cannot provide information on secureboot variable storage.
    if (!GetVariableType(NULL, NULL, Attributes, &varType))
    {
        EMSG("Query by attributes error: Cannot query variables of this type");
        MaxVarStorage = 0;
        RemainingVarStorage = 0;
        MaxVarSize = 0;
        return;
    }

    PLIST_ENTRY head = &VarInfo[varType].Head;
    PLIST_ENTRY cur = head->Flink;
    while ((cur) && (cur != head))
    {
        pVar = (PUEFI_VARIABLE)cur;
        
        // From UEFI Spec 2.7:
        // MaximumVariableSize includes overhead needed to store the variable,
        // but not the overhead caused by storing the name.
        VarSize = ROUNDUP(pVar->AllocSize - pVar->NameSize, NV_AUTHVAR_ALIGNMENT);

        while(pVar->NextOffset) {
            pVar = (PUEFI_VARIABLE)(pVar->BaseAddress + pVar->NextOffset);
            VarSize += pVar->AllocSize;
        }

        MaxSize = MAX(MaxSize, VarSize);

        cur = cur->Flink;
    }

    // Fill in output values
    if (MaxVarStorage)
    {
        // This implementation does not need to differentiate between types.
        // We can store any type of variable.
        *MaxVarStorage = NV_AUTHVAR_SIZE;
        FMSG("Max storage is 0x%x", (UINT32)MaxVarStorage);
    }

    if (RemainingVarStorage)
    {
        *RemainingVarStorage = s_nvLimit - s_nextFree - sizeof(UEFI_VARIABLE);
        FMSG("Remaining storage is 0x%x", (UINT32)RemainingVarStorage);
    }

    if (MaxVarSize)
    {
        *MaxVarSize = MaxSize;
        FMSG("Max variable size is 0x%x", (UINT32)MaxSize);
    }

    return;
}

//
// Helper function(s)
//

static
BOOLEAN
CompareEntries(
    PCUNICODE_STRING     Name,      // IN
    PCGUID               Guid,      // IN
    PUEFI_VARIABLE       Var        // IN
)
/*++

    Routine Description:

        Routine for checking if a variable matches a name and GUID.

    Arguments:

        Name - The name to match

        Guid - The GUID to match

        Var - The first node of the variable to compare against

    Returns:

        TRUE if the same, FALSE otherwise

--*/
{    
    BOOLEAN retVal = FALSE;

    // First, matching GUIDS?
    if (memcmp(Guid, &Var->VendorGuid, sizeof(GUID)) == 0)
    {
        // Ok, name strings of the same length?
        // When NameSize was set any  extra trailing characters beyond the null
        // terminator were ignored, so it should correctly match Name->Length.
        if (Name->Length == (Var->NameSize - sizeof(WCHAR)))
        {
            // Yes, do they match? (case sensitive!)
            if (wcscmp(Name->Buffer, (PWCHAR)(Var->BaseAddress + Var->NameOffset)) == 0)
            {
                // Win.
                retVal = TRUE;
            }
        }
    }
    return retVal;
}

static
BOOLEAN
GetVariableType(
    PCWSTR      VarName,        // IN
    PCGUID      VendorGuid,     // IN
    ATTRIBUTES  Attributes,     // IN
    PVARTYPE    VarType         // OUT
)
/*++

    Routine Description:

        Function for determining Non-volatile variable type based on
            attributes, and optionally name and GUID.

    Arguments:

        VarName - Name of the variable being searched, NULL to ignore

        VendorGuid - GUID of the variable, NULL to ignore

        Attributes - UEFI attributes of the variable

        VarType - Storage for result

    Returns:

        TRUE - Success, VarType contains variable type

        FALSE - Appended or deleted data, VarType not updated

--*/
{
    // An empty attributes field or guid means this is deleted data
    if (!(Attributes.Flags) || (VendorGuid != NULL && !memcmp(VendorGuid, &GUID_NULL, sizeof(GUID))))
    {
        return FALSE;
    }

    // VarName and VendorGuid may be NULL if we are just determining what
    // type of attributes we have.
    if (VendorGuid != NULL && VarName != NULL && IsSecureBootVar(VarName, VendorGuid))
    {
        *VarType = VTYPE_SECUREBOOT;
        return TRUE;
    }

    // Runtime Auth?
    if ((Attributes.RuntimeAccess) && (Attributes.TimeBasedAuth))
    {
        *VarType = VTYPE_PVT_AUTHENTICATED;
        return TRUE;
    }
    
    // Boot only?
    if ((Attributes.BootService) && !(Attributes.RuntimeAccess))
    {
        *VarType = VTYPE_BOOT;
        return TRUE;
    }

    // None of the above (but assumed NonVolatile).
    *VarType = VTYPE_GENERAL;
    return TRUE;
}

static
BOOLEAN
IsSecureBootVar(
    PCWSTR  VarName,        // IN
    PCGUID  VendorGuid      // IN
)
/*++

    Routine Description:

        Function for checking if a variable is one of DB, DBX, KEK or PK

    Arguments:

        VarName - Name of the variable being searched

        VendorGuid - GUID of the variable

    Returns:

        TRUE if secureboot variable, FALSE otherwise

--*/
{
    BOOLEAN retVal = FALSE;

    // Without (name, guid) we don't know one way or the other
    if (!(VarName) || !(VendorGuid))
    {
        retVal = FALSE;
        goto Cleanup;
    }

    // db/dbx
    if (memcmp(VendorGuid, &EfiSecurityDatabaseGUID, sizeof(GUID)) == 0)
    {
        if (!(wcscmp(VarName, EFI_IMAGE_SECURITY_DATABASE)) ||
            !(wcscmp(VarName, EFI_IMAGE_SECURITY_DATABASE1)))
        {
            retVal = TRUE;
            goto Cleanup;
        }
    }

    // KEK/PK
    if (memcmp(VendorGuid, &EfiGlobalDatabaseGUID, sizeof(GUID)) == 0)
    {
        if (!(wcscmp(VarName, EFI_KEK_SECURITY_DATABASE)) ||
            !(wcscmp(VarName, EFI_PLATFORMKEY_VARIABLE)))
        {
            retVal = TRUE;
            goto Cleanup;
        }
    }

    // No match
    retVal = FALSE;

Cleanup:
    return retVal;
}