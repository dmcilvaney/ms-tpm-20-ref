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
MergeAdjacentBlocks (
    PUEFI_VARIABLE FirstElement
);

BOOLEAN
ReclaimVariable(
    PUEFI_VARIABLE pVar
);

UINT32
AuthVarInitStorage(
    UINT_PTR StartingOffset
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
 * NV backed byte array (s_NV) is iterated through to find each block.
 * 
 * A variable's data may be spread across multiple blocks via a linked
 * list. This list is represented via relative offset values in each block.
 * 
 * For each block:
 *      - Previous runs of the memory reclamation code may have removed
 *          a variable which broke another variable into multiple blocks.
 *          Merge these adjacent blocks into a single large block.
 *      - Is the space used by the current block smaller than the 
 *          allocated space (not less than min alignment)?
 *      - Or has the variable been deleted?
 *      - If yes to either then find the next variable, skipping over
 *          deleted variables along the way.
 *      - Move the next (non-deleted) block forward into the free space.
 *      - Increase the allocation size of that block so there is no
 *          gap left. When the block is processed that gap will be
 *          closed.
 *      - If the current block has a NextOffset link to another node
 *          in a list:
 *              - Keep track of the current node so the offset can be
 *                  updated if the next node is moved forwards.
 *      - Check the list of tracked blocks to see if any were linked
 *          to the next block, if so update the link and remove them
 *          from the list since the next block has reached it's final
 *          location.
 *      - TODO:
 *          Merge linked blocks as we find them
 */

#if (TRACE_LEVEL < TRACE_DEBUG)
#define DumpAuthvarMemory()   (void)0
#else
#define DumpAuthvarMemory()   DumpAuthvarMemoryImpl()
#endif

VOID
DumpAuthvarMemoryImpl(VOID)
{
    PUEFI_VARIABLE pVar = (PUEFI_VARIABLE)ROUNDUP((UINT_PTR)&(s_NV[NV_AUTHVAR_START]), NV_AUTHVAR_ALIGNMENT);
    PUEFI_VARIABLE pLinkVar;

    int mainCounter = 0, linkCounter;
    bool linkBitArray[NV_AUTHVAR_SIZE / sizeof(UEFI_VARIABLE)] = {0};

    DMSG("\t================================");
    DMSG("\tStart of Authvar Memory at  0x%lx:", (UINT_PTR)s_NV);
    DMSG("");
    DMSG("\t#Num:  Offset( Address ) | Allocation( Data Size) | State | Link To | <--->");
    while (((UINT_PTR)pVar - (UINT_PTR)s_NV) < s_nextFree) {
        
        if (pVar->AllocSize == 0) {
            DMSG("ERROR! Memory is bad!");
            break;
        }

        mainCounter++;
        linkCounter = 0;
        if (pVar->NextOffset) {
            pLinkVar = pVar;
            linkCounter = mainCounter;
            // Run through the list until we find our node, keeping track of numbering on the way
            // Note: pVar->BaseAddress may not have been updated yet, use actual address.
            while((UINT_PTR)pLinkVar != (UINT_PTR)pVar + pVar->NextOffset) {
                linkCounter++;
                pLinkVar = (PUEFI_VARIABLE)((UINT_PTR)pLinkVar + pLinkVar->AllocSize);
            }
            linkBitArray[linkCounter] = true;
        }

        UINT_PTR offset = pVar->BaseAddress - (UINT_PTR)s_NV;
        //Check if variable has been deleted
        const char *type = (memcmp(&(pVar->VendorGuid), &GUID_NULL, sizeof(GUID)) ?  "   " : "DEL");
        //Check if its a link variable
        const char *linkIn = (linkBitArray[mainCounter] ? "<-" : "");
        const char *linkMiddle = (linkBitArray[mainCounter] || pVar->NextOffset ? "--" : "");
        const char *linkOut = (pVar->NextOffset ? "->" : "");

        DMSG("\t#%3d: %#7lx(%#9lx) | A: %#7x(D: %#7x) |  %s  | Next:%-2d | %s%s%s",
                mainCounter, offset, (UINT_PTR)pVar, pVar->AllocSize, pVar->DataSize, type,
                linkCounter, linkIn, linkMiddle, linkOut);
        //DMSG("%s-0x%x(+0x%lx):    (#%d:%s,Link:%d)", linked, pVar->AllocSize, (UINT_PTR)pVar, mainCounter, type, linkCounter);
        pVar = (PUEFI_VARIABLE)((UINT_PTR)pVar + pVar->AllocSize);
    }
    DMSG("\tEnd of authvar memory at 0x%lx: (Max:0x%lx)", (UINT_PTR)&(s_NV[s_nextFree]), (UINT_PTR)&(s_NV[s_nvLimit]));
    DMSG("\t================================");

    // If we run too fast, the serial print can't keep up
    // OP-TEE uses very aggresive optimization, need to work
    // to trick it.
    volatile uint32_t counter0, counter1;
    static volatile uint32_t collector = 1;
    for(counter0 = 1; counter0 < 100; counter0++) {
        for (counter1 = 1; counter1 < 100000; counter1++) {
            collector = (collector + 1) * mainCounter;
        }
    }
    DMSG("%d", collector);
}

VOID
UpdateOffsets(
    UINT_PTR NVOffset,
    UINT32 ShrinkAmount
)
/*++

    Routeine Description:

        Updates any link to the node at NVOffset such that it will now
        point to NVOffset-ShrinkAmount

        Removes any nodes which will no longer be affected by subsequent
        changes to the layout.

    Arguments:

        CurrentNVOffset - Offset of the current variable.
        
        ShrinkAmount - How much the stored variables have been shrunk
--*/
{
    PLIST_ENTRY head = &MemoryReclamationList;
    PLIST_ENTRY cur = head->Flink;
    PMEMORY_RECLAMATION_NODE node;

    DMSG("Updating nodes which point to 0x%lx (0x%lx), shrink:0x%x)", NVOffset, NVOffset + (UINT_PTR)s_NV, ShrinkAmount);
    DMSG("Cur 0x%lx, head 0x%lx", (UINT_PTR)cur, (UINT_PTR)head);
    while ((cur) && (cur != head)) {
        node = (PMEMORY_RECLAMATION_NODE)cur;
        DMSG("Node offset: 0x%lx", node->NV_Offset);
        if(node->NV_Offset == NVOffset) {
            // No longer need to track this node
            DMSG("Done with the node at 0x%lx", (UINT_PTR)node->pVar);
            DMSG("Offset was 0x%lx, now its 0x%lx", node->NV_Offset, node->NV_Offset - ShrinkAmount);
            DMSG("(0x%lx -> 0x%lx)", node->NV_Offset + (UINT_PTR)s_NV, node->NV_Offset - ShrinkAmount + (UINT_PTR)s_NV);
            node->pVar->NextOffset -= ShrinkAmount;
            RemoveEntryList(cur);
            cur = cur->Flink;
            TEE_Free(node);
        } else {
            cur = cur->Flink;
        }
    }
}

VOID
TrackOffset(
    PUEFI_VARIABLE pVar
)
/*++

    Routine Description:

        Track this variable so any changes to the memory
        layout may be reflected in its NextOffset value.

    Arguments:

        pVar - Variable to track

--*/
{
    PMEMORY_RECLAMATION_NODE newNode = TEE_Malloc(sizeof(MEMORY_RECLAMATION_NODE), TEE_USER_MEM_HINT_NO_FILL_ZERO);
    if (!newNode) {
        EMSG("Out of memory during initialization, fatal error");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
    }

    newNode->pVar = pVar;
    newNode->NV_Offset = (UINT_PTR)pVar + pVar->NextOffset - (UINT_PTR)s_NV;
    DMSG("F 0x%lx, B 0x%lx", (UINT_PTR)MemoryReclamationList.Flink, (UINT_PTR)MemoryReclamationList.Blink);
    InsertTailList(&MemoryReclamationList, &(newNode->List));
    DMSG("F 0x%lx, B 0x%lx", (UINT_PTR)MemoryReclamationList.Flink, (UINT_PTR)MemoryReclamationList.Blink);
    DMSG("Tracking a variable which points to 0x%lx (0x%lx)", newNode->NV_Offset, newNode->NV_Offset + (UINT_PTR)s_NV);
}

VOID
MergeAdjacentBlocks (PUEFI_VARIABLE FirstBlock)
/*++
    Routine Description:

        Merge all adjacent blocks of a variable together.
        This may occur when another variable was deleted in between
        the linked blocks.

        The first block is expanded to include the next adjacent block's
        allocated space, and the next offset is updated. The data from
        the adjacent block is then added to the first. All subsequent
        blocks, if they are also adjacent to the new expanded block, are
        merged.

    Arguments:

        pVar - Pointer to a block of a variable which should be
            merged with any adjacent elements if they exist. This block
            does not need to be the head of the list.
--*/
{
    PUEFI_VARIABLE AdjacentBlock;
    UINT32 SourceOffset, DestinationOffset, MoveSize;

    DMSG("Checking for merge: NO: 0x%lx, nAC: 0x%x", FirstBlock->NextOffset, FirstBlock->AllocSize);

    while (FirstBlock->NextOffset != 0 && 
            FirstBlock->NextOffset == FirstBlock->AllocSize) {
        DMSG("Variable at 0x%lx has an adjacent block", (UINT_PTR)FirstBlock);
        AdjacentBlock = (PUEFI_VARIABLE)(FirstBlock->BaseAddress + FirstBlock->NextOffset);

        if ((UINT_PTR)(AdjacentBlock + AdjacentBlock->AllocSize) >= (UINT_PTR)&(s_NV[s_nvLimit]))
        {
            // Sign of corruption, we don't want to add unknown data to a variable.
            TEE_Panic(TEE_ERROR_BAD_STATE);
        }

        if (AdjacentBlock->NextOffset != 0)
        {
            DMSG("Merged block will have next offset 0x%lx", AdjacentBlock->NextOffset + FirstBlock->AllocSize);
            FirstBlock->NextOffset = AdjacentBlock->NextOffset + FirstBlock->AllocSize;
        } else {
            DMSG("Merged block will have offset 0");
            FirstBlock->NextOffset = 0;
        }
        DMSG("Merged block will have allocation size 0x%x", FirstBlock->AllocSize + AdjacentBlock->AllocSize);
        FirstBlock->AllocSize += AdjacentBlock->AllocSize;
        MoveSize = AdjacentBlock->DataSize;
        DMSG("Merged block will have data size (0x%x+0x%x) = 0x%x", FirstBlock->DataSize, AdjacentBlock->DataSize, FirstBlock->DataSize + AdjacentBlock->DataSize);

        SourceOffset = (AdjacentBlock->BaseAddress + AdjacentBlock->DataOffset) - (UINT_PTR)s_NV;
        DestinationOffset = (FirstBlock->BaseAddress + FirstBlock->DataOffset + FirstBlock->DataSize) - (UINT_PTR)s_NV;
        DMSG("Moving 0x%x bytes from 0x%lx to 0x%lx", MoveSize, (AdjacentBlock->BaseAddress + AdjacentBlock->DataOffset), (FirstBlock->BaseAddress + FirstBlock->DataOffset + FirstBlock->DataSize));
        _plat__NvMemoryMove(SourceOffset, DestinationOffset, MoveSize);
        
        FirstBlock->DataSize += MoveSize;
        _plat__MarkDirtyBlocks(AdjacentBlock->BaseAddress - (UINT_PTR)s_NV, sizeof(UEFI_VARIABLE));
    }
}

BOOLEAN
ReclaimVariable(
    PUEFI_VARIABLE pVar
)
/*++

    Routine Description:

        Memory reclamation for AuthVar storage. Shrinks or
        removes a variable if it has been deleted or had its
        data reduced. Moves the next variable in memory to remove
        gaps while increasing its allocated size. A subsequent call
        to ReclaimMemory on that variable will similarrly attempt
        to reclaim that wasted space.

        Maintains a list of nodes which may need to have their offsets
        updated and will udpate them as needed.

    Arguments:

        pVar - Pointer to the variable to shrink/remove

    Returns:

        TRUE - Variable was deleted

        FALSE - Variable was left in place (but possibly shrunk)
--*/
{
    UINT32 newVariableSize, wastedSpace, newAlloc, shrinkAmmount, deleteAmmount, nextVarOldAllocSize;
    PUEFI_VARIABLE nextVar;
    BOOLEAN wasDeleted = FALSE;

    DMSG("Reclaiming memory at 0x%lx\n", (UINT_PTR)pVar);

    // Sanity check size field
    if (pVar->AllocSize == 0) {
        EMSG("Detected corruption in authenticated variable store");
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }

    // Check if the variable has been deleted
    if(!memcmp(&(pVar->VendorGuid), &GUID_NULL, sizeof(GUID))) {
        DMSG("Deleted variable!");
        newVariableSize = 0;
        wasDeleted = TRUE;
    } else {
        // If possible, merge adjacent blocks which are fragmented.
        MergeAdjacentBlocks(pVar);

        // If this variable still has multiple blocks it may be necessary to update
        // the offsets as memory is reclaimed.
        DMSG("Var at 0x%lx has offset 0x%lx", (UINT_PTR)pVar, pVar->NextOffset);
        if (pVar->NextOffset) {
            TrackOffset(pVar);
        }

        DMSG("Offset:0x%lx, Size:0x%x", pVar->DataOffset, pVar->DataSize);
        newVariableSize = pVar->DataOffset + pVar->DataSize;
    }

    wastedSpace = pVar->AllocSize - newVariableSize;
    DMSG("Total size is 0x%x, Wasted space is 0x%x", newVariableSize, wastedSpace);

    // We need to remain alligned, don't reclaim gaps smaller
    // than our alignment.
    if (wastedSpace < NV_AUTHVAR_ALIGNMENT) {
        DMSG("Can't reclaim less than 0x%x", NV_AUTHVAR_ALIGNMENT);
        //
        // If we aren't moving the next variable, we don't need to track
        // offsets to it anymore.
        //
        UpdateOffsets((UINT_PTR)pVar + pVar->AllocSize - (UINT_PTR)s_NV, 0);
        return 0;
    }

    newAlloc = ROUNDUP(newVariableSize, NV_AUTHVAR_ALIGNMENT);
    shrinkAmmount = pVar->AllocSize - newAlloc;

    DMSG("We now need 0x%x, 0x%x less than before", newAlloc, shrinkAmmount);

    // Search ahead for the first non-deleted variable, or the end of memory
    // We may as well colapse multiple variables in one go.
    // If our memory becomes corrupt the next variable may have alloc size 0.
    // This will be caught on the next iteration of ReclaimVariable().
    nextVar = (PUEFI_VARIABLE)(pVar->BaseAddress + pVar->AllocSize);
    DMSG("Next variable is at 0x%lx", (UINT_PTR)nextVar);
    deleteAmmount = 0;
    while (((UINT_PTR)nextVar - (UINT_PTR)s_NV < s_nextFree) &&
            !memcmp(&(nextVar->VendorGuid), &GUID_NULL, sizeof(GUID)) &&
            nextVar->AllocSize > 0) {

        DMSG("Found deleted variable of size 0x%x", nextVar->AllocSize);
        deleteAmmount += nextVar->AllocSize;
        // nextVar's BaseAddress has not been updated yet, use actual address.
        DMSG("Now checking for another deleted variable at 0x%lx",(UINT_PTR)nextVar);
        nextVar = (PUEFI_VARIABLE)((UINT_PTR)nextVar + nextVar->AllocSize);
    }

    pVar->AllocSize -= shrinkAmmount;

    // No need to move data at the end of storage, just colapse the end pointer
    if((UINT_PTR)nextVar - (UINT_PTR)s_NV >= s_nextFree) {
        DMSG("Last variable, shrinking s_nextFree by 0x%x", (shrinkAmmount + deleteAmmount));
        s_nextFree -= (shrinkAmmount + deleteAmmount);
        DMSG("s_nextFree is now 0x%lx (0x%lx)", s_nextFree, (UINT_PTR)&s_NV[s_nextFree]);
        // It is important to clear data from the end of the list. This allows us to detect
        // corruption (ie s_nextFree points past the end of actual data due to a power failure
        // during write back).
        _plat__NvMemoryClear(s_nextFree, shrinkAmmount + deleteAmmount);
        
        PLIST_ENTRY head = &MemoryReclamationList;
        PLIST_ENTRY cur = head->Flink;
        if(head != cur) {
            DMSG("List broken?");
            DMSG("Was looking for 0x%lx",((PMEMORY_RECLAMATION_NODE)head->Flink)->NV_Offset);
            TEE_Panic(TEE_ERROR_BAD_STATE);
        }
    } else {
        // Move the next variable into the extra space, then
        // expand that variable so it is allocated the entire gap.
        // This space will be reclaimed in the next call to ReclaimMemory().
        DMSG("Size of nextVar: 0x%x, distance to move: shrink amount:0x%x + delete ammount:0x%x", nextVar->AllocSize, shrinkAmmount, deleteAmmount);

        // If s_nextFree is not consistent with actual data, we will run into an all zero block.
        // This is a sign of data corruption and is considered an error.
        if (nextVar->AllocSize == 0) {
            EMSG("Detected corruption in authenticated variable store");
            TEE_Panic(TEE_ERROR_BAD_STATE);
        }

        nextVarOldAllocSize = nextVar->AllocSize;

        nextVar->AllocSize += shrinkAmmount + deleteAmmount;
        DMSG("Next var now has alloc size of 0x%x", nextVar->AllocSize);

        // Keeping the internal structure up to date is required to allow
        // printing of the current memory state.
        if(nextVar->NextOffset) {
            nextVar->NextOffset += shrinkAmmount + deleteAmmount;
        }

        DMSG("Moving offset 0x%lx to 0x%lx (size=0x%x)", (UINT_PTR)nextVar - (UINT_PTR)s_NV, pVar->BaseAddress + pVar->AllocSize - (UINT_PTR)s_NV, nextVar->AllocSize);
        DMSG("(0x%lx to 0x%lx)", (UINT_PTR)nextVar, pVar->BaseAddress + pVar->AllocSize);
        _plat__NvMemoryMove((UINT_PTR)nextVar - (UINT_PTR)s_NV,
                            pVar->BaseAddress + pVar->AllocSize - (UINT_PTR)s_NV,
                            nextVarOldAllocSize);


        // Update any links which pointed to nextVar, which has been moved to colapse
        // a gap
        UpdateOffsets((UINT_PTR)nextVar - (UINT_PTR)s_NV, shrinkAmmount + deleteAmmount);
    }

    return wasDeleted;
}

UINT32
AuthVarInitStorage(
    UINT_PTR StartingOffset
)
/*++

    Routine Description:

        AuthVar storage initializaion routine

    Arguments:

        StartingOffset - Offset from 0 of first byte of AuthVar NV storage

    Returns:

        0 - Failure

        1 - Success

--*/
{
    NV_AUTHVAR_STATE authVarState;
    PUEFI_VARIABLE pVar;
    PCWSTR name;
    PCGUID guid;
    VARTYPE varType;
    VARTYPE i;

    // Sanity check on storage offset
    if ((StartingOffset != s_nextFree))
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
    DMSG("nextFree/NvEnd:0x%lx, s_nvLimit:0x%lx (size:%lx)", (UINT_PTR)authVarState.NvEnd, s_nvLimit, NV_AUTHVAR_SIZE);
    if (!(s_nextFree < s_nvLimit))
    {
        DMSG("FAILED: Inconsistent nextFree/NvEnd.");
        return 0;
    }

    DMSG("s_NV enforced alignment is 0x%x bytes", NV_AUTHVAR_ALIGNMENT);

    // Init in-memory lists
    for (i = 0; i < VTYPE_END; i++) {
        InitializeListHead(&(VarInfo[i].Head));
        DMSG("Head %d address is 0x%lx", i, (UINT_PTR)&VarInfo[i].Head);
        DMSG("Head f:0x%lx, Head b:0x%lx", (UINT_PTR)VarInfo[i].Head.Flink, (UINT_PTR)VarInfo[i].Head.Blink);
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
            DMSG("Alignment error! 0x%lx, 0x%lx",
                ROUNDUP((UINT_PTR)&s_NV[s_nextFree], NV_AUTHVAR_ALIGNMENT),
                (UINT_PTR)&s_NV[s_nextFree] );
            TEE_Panic(TEE_ERROR_BAD_STATE);
    }
    pVar = (PUEFI_VARIABLE)ROUNDUP((UINT_PTR)s_NV + StartingOffset, NV_AUTHVAR_ALIGNMENT);

    do {
        // Init before gettype
        pVar->BaseAddress = (UINT_PTR)pVar;
        guid = (PCGUID)&(pVar->VendorGuid);
        name = (PCWSTR)(pVar->BaseAddress + pVar->NameOffset);

        // Check if deleted or appended data entry
        DMSG("Checking state of next variable at 0x%lx", (UINT_PTR)pVar);
        if (GetVariableType(name, guid, pVar->Attributes, &varType))
        {
            // Only track a node if it is the first entry
            if(pVar->NameSize > 0)
            {
                // Add pointer to this var to appropriate in-memory list
                DMSG("Adding variable to lists");
                InsertTailList(&VarInfo[varType].Head, &pVar->List);
            }
        }

        // Attempt to reclaim unused memory from the current variable,
        // then compute pointer to next var. If the current variable was
        // deleted then the next variable will be in the same place.
        if (!ReclaimVariable(pVar)) {
            // Variable was not deleted, move to the next variable
            pVar = (PUEFI_VARIABLE)(pVar->BaseAddress + pVar->AllocSize);
        }

        DMSG("Do: 0x%lx is less than 0x%lx?",((UINT_PTR)pVar - (UINT_PTR)s_NV),s_nextFree);
        DumpAuthvarMemory();
    } while (((UINT_PTR)pVar - (UINT_PTR)s_NV) < s_nextFree);

    authVarState.NvEnd = s_nextFree;
    _admin__SaveAuthVarState(&authVarState);

    // No need to commit NV changes to disk now, wait until data has been modified.
    return 1;
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

        Var - Pointer to the variable's entry in memory. NULL if not found.

        VarType - Type used to determine variable's info and storage

    Returns:

    None

    --*/
{
    UINT32 i;

    DMSG("Search list");

    // Validate parameters
    if (!(UnicodeName) || !(VendorGuid) || !(Var) || !(VarType))
    {
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

    // TODO: REMOVE
    if(*Var) {
        DMSG("Found match");
    } else {
        DMSG("No match");
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
    UINT32 totalNv = 0, uStrLen = 0, extAttribLen = 0;
    VARTYPE varType;
    TEE_Result status = TEE_SUCCESS;

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        DMSG("volatile var");
        // Validate length
        if (DataSize == 0)
        {
            // TODO: I believe there are circumstances under which it is permitted
            //       to create a var with zero DataSize. But I guess we'll cross 
            //       that bridge when we come to it.
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Attempt allocation for variable
        if (!(newVar = TEE_Malloc(sizeof(UEFI_VARIABLE), TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Attempt allocation for variable name
        if (!(newStr  = TEE_Malloc(UnicodeName->MaximumLength, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            TEE_Free(newVar);
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Attempt allocation for variable data
        if (!(newData = TEE_Malloc(DataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            TEE_Free(newVar);
            TEE_Free(newStr);
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Init volatile variable storage
        memset(newVar, 0, sizeof(UEFI_VARIABLE));

        // Guid/Attributes
        newVar->VendorGuid = *VendorGuid;
        newVar->Attributes.Flags = Attributes.Flags;

        // Pointers to name, etc. are proper memory addresses, 
        // not offsets inside the memory map
        newVar->BaseAddress = 0;

        // Init/copy variable name
        newVar->NameSize = UnicodeName->MaximumLength;
        newVar->NameOffset = (UINT_PTR)newStr;
        memmove(newStr, UnicodeName->Buffer, newVar->NameSize);

        DMSG("Unicode name is:");
        DHEXDUMP(newStr, newVar->NameSize);

        // Init/copy variable data
        newVar->DataSize = DataSize;
        newVar->DataOffset = (UINT_PTR)newData;
        memmove(newData, Data, DataSize);

        DMSG("New  volatlie var is at 0x%lx, data at 0x%lx", (UINT_PTR)newVar, (UINT_PTR)newVar->DataOffset);
        DMSG("GUID");
        DHEXDUMP(&newVar->VendorGuid, sizeof(newVar->VendorGuid));

        // Note the lack of a check against ExtendedAttributes.
        // We do not implement authenticated volatile variables.

        DMSG("Updating list of type %d", VTYPE_VOLATILE);
        DMSG("at %lx", (UINT_PTR)&VarInfo[VTYPE_VOLATILE].Head);
        DMSG("we have f=%lx, t=%lx", (UINT_PTR)VarInfo[VTYPE_VOLATILE].Head.Flink, (UINT_PTR)VarInfo[VTYPE_VOLATILE].Head.Blink);

        // Add it to the list
        InsertTailList(&(VarInfo[VTYPE_VOLATILE].Head), &newVar->List);

        DMSG("Now we have f=%lx, t=%lx", (UINT_PTR)VarInfo[VTYPE_VOLATILE].Head.Flink, (UINT_PTR)VarInfo[VTYPE_VOLATILE].Head.Blink);

        // Success
        status = TEE_SUCCESS;
        goto Cleanup;
    }
    else
    {
        // Nope, create new non-volatile variable.
        DMSG("non-volatile");
        // Which list is this variable destined for?
        if (!GetVariableType(UnicodeName->Buffer, VendorGuid, Attributes, &varType))
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Get strlen of unicode name
        uStrLen = UnicodeName->MaximumLength;

        // Get size if extended attributes (if provided)
        if (ExtAttributes)
        {
            extAttribLen = sizeof(EXTENDED_ATTRIBUTES) + ExtAttributes->PublicKey.DataSize;
        }
        else
        {
            extAttribLen = 0;
        }

        // Total NV requirement to store this var
        totalNv = sizeof(UEFI_VARIABLE) + uStrLen + DataSize + extAttribLen;

        DMSG("Storing 0x%x bytes (variable + name + data)", totalNv);

        DMSG("t: %x snF: %lx nvLim: %lx", totalNv, s_nextFree, s_nvLimit);
        // Is there enough room on this list and in NV?
        if ((totalNv + s_nextFree) > s_nvLimit)
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Init pointers to new fields
        DMSG("s_NV is at 0x%lx", (UINT_PTR)s_NV);
        DMSG("offset is 0x%lx", s_nextFree);

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

        DMSG("newVar: 0x%lx", (UINT_PTR)newVar);
        newVar->BaseAddress = (UINT_PTR)newVar;
        newStr = (PWSTR)((UINT_PTR)newVar + sizeof(UEFI_VARIABLE));
        DMSG("New string is at 0x%lx, with length 0x%x", (UINT_PTR)newStr, uStrLen);
        newExt = (PEXTENDED_ATTRIBUTES)((UINT_PTR)newStr + uStrLen);
        DMSG("New ext is at 0x%lx, with length 0x%x", (UINT_PTR)newExt, extAttribLen);
        newData = (PBYTE)((UINT_PTR)newExt + extAttribLen);
        DMSG("New data is at 0x%lx, with length 0x%x", (UINT_PTR)newData, DataSize);

        DMSG("create");


        DMSG("vendorguid is 0x%lx",(UINT_PTR)VendorGuid);
        // Init variable structure
        newVar->VendorGuid = *VendorGuid;
        newVar->Attributes.Flags = Attributes.Flags;
        newVar->NameSize = uStrLen;
        newVar->NameOffset = (UINT_PTR)newStr - newVar->BaseAddress;
        DMSG("String offset is 0x%lx", newVar->NameOffset);
        DMSG("create");
        // Copy name and data
        memmove(newStr, UnicodeName->Buffer, uStrLen);

        // Size of var structure before any appended data that may come later
        // Make sure all structures are aligned.
        newVar->AllocSize = ROUNDUP(totalNv, NV_AUTHVAR_ALIGNMENT);
        DMSG("create");
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
        DMSG("create");
        // Data fields
        newVar->DataSize = DataSize;
        newVar->DataOffset = (UINT_PTR)newData - newVar->BaseAddress;
        memmove(newData, Data, DataSize);

        // Creating this var we don't yet have appended data
        newVar->NextOffset = 0;
        DMSG("create");
        // We've touched NV so, write back.
        _plat__MarkDirtyBlocks(newVar->BaseAddress - (UINT_PTR)s_NV, newVar->AllocSize);

        DMSG("Updating s_nextFree from 0x%lx by incrementing %x (%x)", s_nextFree, newVar->AllocSize, totalNv);
        DMSG("0x%lx -> 0x%lx", (UINT_PTR)s_NV + s_nextFree, (UINT_PTR)s_NV + s_nextFree + newVar->AllocSize);
        // Update offset to next free byte alligned to 64 bits
        s_nextFree += newVar->AllocSize;
        DMSG("create");
        NV_AUTHVAR_STATE authVarState;
		authVarState.NvEnd = s_nextFree;
		_admin__SaveAuthVarState(&authVarState);

        DMSG("Updating list of type %d", varType);
        DMSG("at 0x%lx", (UINT_PTR)&VarInfo[varType].Head);
        DMSG("we have f=%lx, t=%lx", (UINT_PTR)VarInfo[varType].Head.Flink, (UINT_PTR)VarInfo[varType].Head.Blink);

        // Update the in-memory list
        InsertTailList(&VarInfo[varType].Head, &newVar->List);
        DMSG("Now we have f=%lx, t=%lx", (UINT_PTR)VarInfo[varType].Head.Flink, (UINT_PTR)VarInfo[varType].Head.Blink);
        DMSG("Done insert");
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
    PUEFI_VARIABLE varIter;
    UINT32 size, length;
    TEE_Result status = TEE_SUCCESS;

    DMSG("ret");
    DMSG("Getting value from 0x%lx", (UINT_PTR)Var);
    DMSG("We can store 0x%x bytes back", ResultBufLen);

    size = 0;
    
    // Detect integer overflow
    if (((UINT32)ResultBuf + ResultBufLen) < (UINT32)ResultBuf)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    //Calculate the total size required
    varIter = Var;
    do {
        DMSG("Adding size 0x%x", varIter->DataSize);
        DMSG("Next is 0x%lx", varIter->NextOffset);
        size += varIter->DataSize;
        nextOffset = varIter->NextOffset;
        varIter = (PUEFI_VARIABLE)(varIter->BaseAddress + nextOffset);
    } while ((nextOffset));
    DMSG("Total size is 0x%x", size);

    DMSG("ResultBufLen:0x%x, we want to store 0x%x", ResultBufLen, (size + sizeof(VARIABLE_GET_RESULT)));

    if (ResultBufLen < (size + sizeof(VARIABLE_GET_RESULT)))
    {
        DMSG("Short buffer");
        status = TEE_ERROR_SHORT_BUFFER;
        ResultBuf->DataSize = size;
        goto Cleanup;
    }

DMSG("ret");
    // Copy variable data
    ResultBuf->Attributes = Var->Attributes.Flags;
    ResultBuf->DataSize = size;
    ResultBuf->Size = sizeof(VARIABLE_GET_RESULT);
DMSG("ret");
    // Init for copy
    dstPtr = ResultBuf->Data;
    limit = dstPtr + ResultBufLen;
DMSG("ret");
    // Do the copy (accross appended data entries if necessary)
    varIter = Var;
    do {
        // Calculate length and copy data
        length = varIter->DataSize;

        DMSG("Data:0x%lx", varIter->DataOffset + varIter->BaseAddress);
        DMSG("ret");
        DMSG("Copying 0x%x bytes from 0x%lx to 0x%p", length, (UINT_PTR)(varIter->DataOffset + varIter->BaseAddress), dstPtr);
        memcpy(dstPtr, (PBYTE)(varIter->DataOffset + varIter->BaseAddress), length);
        DMSG("ret");
        // Adjust destination pointer
        dstPtr += length;

        // Pickup offset to next set of appended data (may be zero)
        nextOffset = varIter->NextOffset;

        // Calculate pointer to next set of appended data
        varIter = (PUEFI_VARIABLE)(varIter->BaseAddress + nextOffset);

        // Loop if we have another entry or we haven't written size bytes yet
    } while ((nextOffset != 0) && (dstPtr < limit));

Cleanup:
    if (BytesWritten) // or needed..
    {
        *BytesWritten = size + sizeof(VARIABLE_GET_RESULT);
        DMSG("Required buffer size is 0x%x bytes", *BytesWritten);
    }

    return status;
}

TEE_Result
DeleteVariable(
    PUEFI_VARIABLE  Var,
    VARTYPE         VarType,
    ATTRIBUTES      Attributes
)
{
    UINT_PTR NextOffset;
    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        TEE_Free((PBYTE)Var->DataOffset);
        TEE_Free((PBYTE)Var->NameOffset);
        TEE_Free((PBYTE)Var);
    }
    else {
        do {
            DMSG("Deleting variable at 0x%lx", (UINT_PTR)Var);
            DMSG("Clearing memory at 0x%lx (offset 0x%lx, + 0x%x)", (UINT_PTR)&(Var->VendorGuid), (UINT_PTR)&(Var->VendorGuid) - (UINT_PTR)s_NV, sizeof(GUID));
            _plat__NvMemoryWrite((UINT_PTR)&(Var->VendorGuid) - (UINT_PTR)s_NV, sizeof(GUID), &GUID_NULL);
            _plat__NvMemoryClear((UINT_PTR)&(Var->Attributes.Flags) - (UINT_PTR)s_NV, sizeof(Var->Attributes.Flags));
            DMSG("Deleted GUID:");
            DHEXDUMP(&(Var->VendorGuid), sizeof(GUID));

            NextOffset = Var->NextOffset;
            Var = (PUEFI_VARIABLE)(Var->BaseAddress + NextOffset);
        } while (NextOffset != 0);

    }

    DumpAuthvarMemory();
    return TEE_SUCCESS;
}

TEE_Result
AppendVariable(
    PUEFI_VARIABLE          Var,
    VARTYPE                 VarType,
    ATTRIBUTES              Attributes,
    PEXTENDED_ATTRIBUTES    ExtAttributes,
    PBYTE                   Data,
    UINT32                  DataSize
)
/*++

    Routine Description:

        Function for appending an existing variable

    Arguments:

        Var - Pointer to the variable's entry in memory.

        VarType - Which variable list is Var on?

        Attibutes - UEFI variable attributes

        ExtAttributes - Pointer to ExtendedAttributes (auth only)

        Data - Pointer to the data

        DataSize - Size in bytes of Data

    Returns:

        TEE_Result

--*/
{
    TEE_Result  status = TEE_SUCCESS;
    DMSG("Append variable");

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        DMSG("Volatile append");
        PBYTE dstPtr = NULL;
        UINT32 newSize = 0;

        // TODO: CHECK FOR OVERFLOW
        newSize = Var->DataSize + DataSize;

        // Attempt allocation
        if (!(dstPtr = TEE_Malloc(newSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
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
        DMSG("Non volatile append");

        PUEFI_VARIABLE varPtr = NULL, newVar = NULL;
        PBYTE apndData = NULL;
        UINT32 apndSize = 0, extAttribLen = 0;

        // Calculate space required for additional data. (Note that 
        // we use a UEFI_VARIABLE as a container for appended data).
        apndSize = sizeof(UEFI_VARIABLE) + DataSize;
        DMSG("We need to add 0x%x bytes (%x + %x)", apndSize, sizeof(UEFI_VARIABLE), DataSize);

        // Is there enough room on the list and in NV?
        if ((apndSize + s_nextFree) > s_nvLimit)
        {
            DMSG("No room");
            DMSG("s_nextFree is 0x%lx, s_nvLimit is 0x%lx, trying to append 0x%x", s_nextFree, s_nvLimit, apndSize);
            DMSG("(0x%lx, 0x%lx)",(UINT_PTR)&(s_NV[s_nextFree]), (UINT_PTR)&(s_NV[s_nvLimit]));
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Ensure that we have consistency in args and var info
        if (ExtAttributes && (Var->ExtAttribOffset == 0))
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Find the end of the chain. varPtr will point to the end of the chain.
        varPtr = Var;
        DMSG("varPtr next offset = 0x%lx", varPtr->NextOffset);
        while (varPtr->NextOffset)
        {
            DMSG("LastVar next offset = 0x%lx", varPtr->NextOffset);
            varPtr = (PUEFI_VARIABLE)(varPtr->BaseAddress + varPtr->NextOffset);
            DMSG("lastVar @ 0x%lx",(UINT_PTR)varPtr);
        }

        // This is the last variable, we can just extend the end of memory.
        if((UINT_PTR)(varPtr->BaseAddress + varPtr->AllocSize) == (UINT_PTR)&s_NV[s_nextFree]) {
            DMSG("End of memory, just expand");
            apndData = (PBYTE)(varPtr->BaseAddress + varPtr->DataOffset + varPtr->DataSize);
            DMSG("Adding 0x%x bytes by extending the existing variable", DataSize);
            _plat__NvMemoryWrite((UINT_PTR)apndData - (UINT_PTR)s_NV, DataSize, Data);

            // Update sizes (we know we're adding to the end of NV data)
            DMSG("varPtr had 0x%x bytes of data", varPtr->DataSize);
            varPtr->DataSize += DataSize;
            varPtr->AllocSize = ROUNDUP(varPtr->DataOffset + varPtr->DataSize, NV_AUTHVAR_ALIGNMENT);
            _plat__MarkDirtyBlocks(varPtr->BaseAddress - (UINT_PTR)s_NV, sizeof(UEFI_VARIABLE));
            DMSG("varPtr now has 0x%x bytes of data", varPtr->DataSize);

            // No need to create additional nodes later.
            DataSize = 0;

            s_nextFree = (varPtr->BaseAddress + varPtr->AllocSize) - (UINT_PTR)s_NV;
            NV_AUTHVAR_STATE authVarState;
            authVarState.NvEnd = s_nextFree;
            _admin__SaveAuthVarState(&authVarState);
        }  

        // There may be data left which could not be included in the existing elements
        if (DataSize > 0) {

            DMSG("Add new variable to hold extra data");
        
            // To satisfy the compiler that allignment is fine use ROUNDUP.
            if(ROUNDUP((UINT_PTR)&s_NV[s_nextFree], NV_AUTHVAR_ALIGNMENT) !=
                (UINT_PTR)&s_NV[s_nextFree] ) {
                    DMSG("Alignment error! 0x%lx, 0x%lx",
                        ROUNDUP((UINT_PTR)&s_NV[s_nextFree], NV_AUTHVAR_ALIGNMENT),
                        (UINT_PTR)&s_NV[s_nextFree] );
                    TEE_Panic(TEE_ERROR_BAD_STATE);
            }
            newVar = (PUEFI_VARIABLE)ROUNDUP((UINT_PTR)&s_NV[s_nextFree], NV_AUTHVAR_ALIGNMENT);
            DMSG("New variable at 0x%lx", (UINT_PTR)newVar);

            newVar->BaseAddress = (UINT_PTR)newVar;
            newVar->List.Flink = newVar->List.Blink = 0;
            newVar->VendorGuid = Var->VendorGuid;
            newVar->Attributes.Flags = Attributes.Flags;
            newVar->NameSize = 0;
            newVar->NameOffset = 0;
            newVar->AllocSize = ROUNDUP(sizeof(UEFI_VARIABLE) + DataSize, NV_AUTHVAR_ALIGNMENT);
            newVar->ExtAttribSize = 0;
            newVar->ExtAttribOffset = 0;
            newVar->DataSize = DataSize;
            apndData = (PBYTE)(newVar->BaseAddress + sizeof(UEFI_VARIABLE));

            newVar->DataOffset = (UINT_PTR)apndData - newVar->BaseAddress;
            DMSG("Updating data pointer in newVar to point to 0x%lx (0x%lx)", newVar->DataOffset + newVar->BaseAddress, newVar->DataOffset);

            // Copy data
            memmove(apndData, Data, DataSize);

            // Update extended attributes, if present
            if (ExtAttributes)
            {
                PEXTENDED_ATTRIBUTES extAttrib;

                // Sanity check sizes
                extAttrib = (PEXTENDED_ATTRIBUTES)(Var->BaseAddress + Var->ExtAttribOffset);
                extAttribLen = sizeof(EXTENDED_ATTRIBUTES) + ExtAttributes->PublicKey.DataSize;
                if (extAttribLen != (sizeof(EXTENDED_ATTRIBUTES) + extAttrib->PublicKey.DataSize))
                {
                    status = TEE_ERROR_BAD_PARAMETERS;
                    goto Cleanup;
                }

                // Copy new extended attribute data
                memmove(extAttrib, ExtAttributes, extAttribLen);
            }

            // Finally, link appended variable data
            varPtr->NextOffset = newVar->BaseAddress - varPtr->BaseAddress;

            // Update the NV memory
            _plat__MarkDirtyBlocks(newVar->BaseAddress - (UINT_PTR)s_NV, newVar->AllocSize);

            s_nextFree += newVar->AllocSize;
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
    VARTYPE                 VarType,
    ATTRIBUTES              Attributes,
    PEXTENDED_ATTRIBUTES    ExtAttributes,
    PBYTE                   Data,
    UINT32                  DataSize
)
/*++

    Routine Description:

        Function for replacing value of an existing volatile variable

    Arguments:

        Var - Pointer to the variable's entry in memory.

        Attibutes - UEFI variable attributes

        ExtAttributes - Pointer to ExtendedAttributes (auth only)

        Data - Pointer to the data

        DataSize - Size in bytes of Data

    Returns:

        TEE_Result

--*/
{
    PBYTE srcPtr, limit;
    PUEFI_VARIABLE dstPtr, varPtr;
    UINT_PTR nextOffset;
    UINT32 length, canFit, remaining;
    TEE_Result  status = TEE_SUCCESS;

    DMSG("REplacing variable at 0x%lx", (UINT_PTR)Var);

    //
    EXTENDED_ATTRIBUTES NullAttributes = {0};
    if (!memcmp(ExtAttributes, &NullAttributes, sizeof(EXTENDED_ATTRIBUTES))) {
        ExtAttributes = NULL;
    }

    // We don't implement authenticated volatile variables
    if (!(Attributes.NonVolatile) && ExtAttributes)
    {
        DMSG("replace error");
        status = TEE_ERROR_NOT_IMPLEMENTED;
        goto Cleanup;
    }

    // Some parameter checking
    if (((Attributes.TimeBasedAuth) && !ExtAttributes) ||
        (!(Attributes.TimeBasedAuth) && ExtAttributes))
    {
        DMSG("replace error");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        // Yes. Make sure variable doesn't indicate APPEND_WRITE.
        if ((Attributes.AppendWrite))
        {
            DMSG("replace error");
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

    // Calculate the amount of NV we already have for this variable
    canFit = Var->AllocSize - Var->DataOffset;
    DMSG("Alloc: 0x%x, DS: 0x%x, DO: 0x%lx", Var->AllocSize, Var->DataSize, Var->DataOffset);
    if (DataSize > canFit) {
        // We are increasing our allocation, make sure a new variable will fit.
        length = DataSize - canFit;
        if ((Var->AllocSize + length + s_nextFree) > s_nvLimit)
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }
    }

    DMSG("non-volatile replace");

    // Init for copy
    srcPtr = Data;
    remaining = DataSize;
    limit = Data + DataSize;
    varPtr = Var;

    DMSG("Want to replace with 0x%x bytes of new data", remaining);

    // Do the copy (across appended data entries if necessary).
    // Shrinking a variable can cause fragmentation, reclaiming the
    // lost memory is handled on init.
    do {
        // Determine available space to copy to in the current variable
        canFit = varPtr->AllocSize - varPtr->DataOffset;
        DMSG("WE can fit 0x%x bytes into the current variable at 0x%lx", canFit, (UINT_PTR)varPtr);
        // Length is either the size of this entry or our remaining byte count
        length = MIN(canFit, remaining);

        DMSG("Moving 0x%x bytes into the existing variable", length);

        memmove((PBYTE)(varPtr->BaseAddress + varPtr->DataOffset), srcPtr, length);
        DMSG("Stomping over 0x%lx ot 0x%lx", (varPtr->BaseAddress + varPtr->DataOffset),(varPtr->BaseAddress + varPtr->DataOffset) + length - 1);
        varPtr->DataSize = length;

        _plat__MarkDirtyBlocks(varPtr->BaseAddress - (UINT_PTR)s_NV, varPtr->AllocSize);

        // Adjust remaining and source pointer
        remaining -= length;
        srcPtr += length;

        // Pickup offset to next set of appended data (may be zero)
        nextOffset = varPtr->NextOffset;

        if(nextOffset) {
            DMSG("Continuing on to next element");
            // Calculate pointer to next set of appended data
            varPtr = (PUEFI_VARIABLE)(varPtr->BaseAddress + nextOffset);
        }

        // Loop if we have another entry and we haven't written DataSize bytes yet
    } while ((nextOffset) && (srcPtr < limit));

    // This should never happen, but if we overran our buffer then panic
    if (srcPtr > limit)
    {
        // TODO: SHOULD TEE_PANIC HERE, THIS SHOULD NEVER HAPPEN
        status = TEE_ERROR_OVERFLOW;
        TEE_Panic(TEE_ERROR_OVERFLOW);
        goto Cleanup;
    }

    // Did we run out of space in this variable? If so, append the remaining bytes.
    if (srcPtr < limit)
    {
        // TODO: TEE_PANIC HERE IF nextOffset != 0 (TEE_ERROR_BAD_STATE)
        DMSG("Append a new variable to the end of the list");

        // Append on the rest
        status = AppendVariable(Var, VarType, Attributes, ExtAttributes, srcPtr, remaining);
    }
    else
    {
        DMSG("We managed to fit it all");
        // Data copy was successful, but is some cleanup necessary?
        if (nextOffset)
        {

            // If our next offset != 0 on what should be the last data entry, it's
            // because we 'replaced' the variable data with a smaller data size.
            // Clean up the excess appended data entries now. If there is a nextOffset
            // Var will already point to the next element in the list.
            status = DeleteVariable(varPtr, VarType, Attributes);
            DMSG("Clearing NextOffset from 0x%p", (PBYTE)Var);
            Var->NextOffset = 0;
            _plat__MarkDirtyBlocks(Var->BaseAddress - (UINT_PTR)s_NV, Var->AllocSize);
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

    DMSG("Q");

    // Note that since we are not provided a (name,guid) for a query, we
    // cannot provide information on secureboot variable storage.
    if (!GetVariableType(NULL, NULL, Attributes, &varType))
    {
        return;
    }

DMSG("Q");
    PLIST_ENTRY head = &VarInfo[varType].Head;
    PLIST_ENTRY cur = head->Flink;
DMSG("Q");
    while ((cur) && (cur != head))
    {
        pVar = (PUEFI_VARIABLE)cur;
        
        // From UEFI Spec 2.7:
        // MaximumVariableSize includes overhead needed to store the variable,
        // but not the overhead caused by storing the name.
        VarSize = ROUNDUP(pVar->AllocSize - pVar->NameSize, NV_AUTHVAR_ALIGNMENT);
        DMSG("Initial size of var at 0x%lx is 0x%x", (UINT_PTR)pVar, VarSize);

        while(pVar->NextOffset) {
            pVar = (PUEFI_VARIABLE)(pVar->BaseAddress + pVar->NextOffset);
            VarSize += pVar->AllocSize;
            DMSG("\tAdding 0x%x bytes from linked node", pVar->AllocSize);
        }
        
        DMSG("Var has total size 0x%x", VarSize);
        MaxSize = MAX(MaxSize, VarSize);

        cur = cur->Flink;
    }

    DMSG("Max size is 0x%x", (UINT32)MaxSize);

    // Fill in output values
    if (MaxVarStorage)
    {
        // This implementation does not need to differentiate between types.
        // We can store any type of variable. Spec 
        *MaxVarStorage = NV_AUTHVAR_SIZE;
    }

    if (RemainingVarStorage)
    {
        *RemainingVarStorage = s_nvLimit - s_nextFree - sizeof(UEFI_VARIABLE);
    }

    if (MaxVarSize)
    {
        *MaxVarSize = MaxSize;
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

        Routine for comparing two NAME_KEYs

    Arguments:

        Entry0, Entry1 - The two structures to compare

    Returns:

        TRUE if the same, FALSE otherwise

--*/
{    
    BOOLEAN retVal = FALSE;

    //DMSG("Unicode name:");
    //DHEXDUMP(Name->Buffer, Name->MaximumLength);
    //DMSG("Target name at 0x%lx + 0x%lx = 0x%lx:",Var->BaseAddress , Var->NameOffset, Var->BaseAddress + Var->NameOffset);
    //DHEXDUMP(Var->BaseAddress + Var->NameOffset, Var->NameSize);

    //DMSG("Comparing GUIDs at 0x%lx and 0x%lx", (uint32_t)Guid, (uint32_t)&Var->VendorGuid);
    //DHEXDUMP(&Var->VendorGuid, sizeof(Var->VendorGuid));
    // First, matching GUIDS?
    if (memcmp(Guid, &Var->VendorGuid, sizeof(GUID)) == 0)
    {
        //DMSG("Same");
        //DMSG("Mlengh = %d, SearchLengh = %d, checklength = %d", Name->MaximumLength, wcslen(Name->Buffer), wcslen(Var->BaseAddress + Var->NameOffset));
        // Ok, name strings of the same length?
        if (wcslen(Name->Buffer) == wcslen((wchar_t*)(Var->BaseAddress + Var->NameOffset)))
        {
            //DMSG("Comparing Names at 0x%lx and 0x%lx", (uint32_t)Name->Buffer, Var->BaseAddress + (uint32_t)Var->NameOffset);
            // Yes, do they match? (case sensitive!)
            if (wcscmp(Name->Buffer, (wchar_t*)(Var->BaseAddress + Var->NameOffset)) == 0)
            {
                // Win.
                //DMSG("Match!");
                retVal = TRUE;
            }
        }
    }
    //if(!retVal) {
        //DMSG("No Match!");
    //}
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

        Function for determining Non-volatile variable type

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

    // VarName and VendorGuid may be NULL
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

        VariableName - Name of the variable being searched

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