//
// Virual Memory Simulator Homework
// Two-level page table system
// Inverted page table with a hashing system 
// Student Name: 박성만
// Student Number: B411080
// Date : 2018.10

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#define PAGESIZEBITS 12			// page size = 4Kbytes
#define VIRTUALADDRBITS 32		// virtual address space size = 4Gbytes
#define NUMADDRESS 1000000	//주소의 개수 1000000개

typedef struct pageTableEntry {
	int level;				// page table level (1 or 2)
	char valid;
	struct pageTableEntry *secondLevelPageTable;	// valid if this entry is for the first level page table (level = 1)
	int frameNumber;								// valid if this entry is for the second level page table (level = 2)
}pageTableEntry;

 

typedef struct framePage {
	int number;			// frame number
	int pid;			// Process id that owns the frame
	unsigned virtualPageNumber;			// virtual page number using the frame
	struct framePage *lruLeft;	// for LRU 534circular doubly linked list
	struct framePage *lruRight; // for LRU circular doubly linked list
}framePage;

 

typedef struct invertedPageTableEntry {
	int pid;					// process id
	unsigned virtualPageNumber;		// virtual page number
	int frameNumber;			// frame number allocated
	struct invertedPageTableEntry *next;
}invertedPageTableEntry;

 

typedef struct procEntry {
	char *traceName;			// the memory trace name
	int pid;					// process (trace) id
	int ntraces;				// the number of memory traces
	int num2ndLevelPageTable;	// The 2nd level page created(allocated);
	int numIHTConflictAccess; 	// The number of Inverted Hash able Conflict Accesses
	int numIHTNULLAccess;		// The number of Empty Inverted Hash Table Accesses
	int numIHTNonNULLAcess;		// The number of Non Empty Inverted Hash Table Accesses
	int numPageFault;			// The number of page faults
	int numPageHit;		// The number of page hits
	struct pageTableEntry *firstLevelPageTable;
	FILE *tracefp;
}procEntry;

struct framePage *oldestFrame; // the oldest frame pointer

int firstLevelBits, phyMemSizeBits, numProcess;

void initPhyMem(struct framePage *phyMem, int nFrame) {
	int i;
	for (i = 0; i < nFrame; i++) {
		phyMem[i].number = i;
		phyMem[i].pid = -1;
		phyMem[i].virtualPageNumber = -1;
		phyMem[i].lruLeft = &phyMem[(i - 1 + nFrame) % nFrame];
		phyMem[i].lruRight = &phyMem[(i + 1 + nFrame) % nFrame];
	}
	oldestFrame = &phyMem[0];
}

 

void initHashTable(struct invertedPageTableEntry *HashTableEntry, int index) {	// hashtable 초기화 함수
	int i;
	for (i = 0; i < index; i++) {
		HashTableEntry[i].pid = -1;
		HashTableEntry[i].virtualPageNumber = -1;
		HashTableEntry[i].frameNumber = -1;
		HashTableEntry[i].next = NULL;
	}
}

 

void secondLevelVMSim(struct procEntry *procTable, struct framePage *phyMemFrames) {
	int i;
	for (i = 0; i < numProcess; i++) {
		printf("**** %s *****\n", procTable[i].traceName);
		printf("Proc %d Num of traces %d\n", i, procTable[i].ntraces);
		printf("Proc %d Num of second level page tables allocated %d\n", i, procTable[i].num2ndLevelPageTable);
		printf("Proc %d Num of Page Faults %d\n", i, procTable[i].numPageFault);
		printf("Proc %d Num of Page Hit %d\n", i, procTable[i].numPageHit);
		assert(procTable[i].numPageHit + procTable[i].numPageFault == procTable[i].ntraces);
	}
}

 

void invertedPageVMSim(struct procEntry *procTable, struct framePage *phyMemFrames, int nFrame) {
	int i;
	for (i = 0; i < numProcess; i++) {
		printf("**** %s *****\n", procTable[i].traceName);
		printf("Proc %d Num of traces %d\n", i, procTable[i].ntraces);
		printf("Proc %d Num of Inverted Hash Table Access Conflicts %d\n", i, procTable[i].numIHTConflictAccess);
		printf("Proc %d Num of Empty Inverted Hash Table Access %d\n", i, procTable[i].numIHTNULLAccess);
		printf("Proc %d Num of Non-Empty Inverted Hash Table Access %d\n", i, procTable[i].numIHTNonNULLAcess);
		printf("Proc %d Num of Page Faults %d\n", i, procTable[i].numPageFault);
		printf("Proc %d Num of Page Hit %d\n", i, procTable[i].numPageHit);
		assert(procTable[i].numPageHit + procTable[i].numPageFault == procTable[i].ntraces);
		assert(procTable[i].numIHTNULLAccess + procTable[i].numIHTNonNULLAcess == procTable[i].ntraces);
	}
}

 

int main(int argc, char *argv[]) {
	int i;
	int j;
	numProcess = argc - 3;	//Process의 개수
	firstLevelBits = atoi(argv[1]);
	phyMemSizeBits = atoi(argv[2]);

	if (argc < 4) {
		printf("Usage : %s firstLevelBits PhysicalMemorySizeBits TraceFileNames\n", argv[0]); exit(1);
	}

	if (phyMemSizeBits < PAGESIZEBITS) {
		printf("PhysicalMemorySizeBits %d should be larger than PageSizeBits %d\n", phyMemSizeBits, PAGESIZEBITS); exit(1);
	}

	if (VIRTUALADDRBITS - PAGESIZEBITS - firstLevelBits <= 0) {
		printf("firstLevelBits %d is too Big\n", firstLevelBits); exit(1);
	}
	// initialize procTable for two-level page table

	for (i = 0; i < numProcess; i++) {
		// opening a tracefile for the process
		printf("process %d opening %s\n", i, argv[i + 3]);
	}

	int nFrame = (1 << (phyMemSizeBits - PAGESIZEBITS)); 
    assert(nFrame > 0);	//

	printf("\nNum of Frames %d Physical Memory Size %ld bytes\n", nFrame, (1L << phyMemSizeBits));
	printf("=============================================================\n");
	printf("The 2nd Level Page Table Memory Simulation Starts .....\n");
	printf("=============================================================\n");

	procEntry *procTable = (procEntry*)malloc(sizeof(procEntry)*numProcess);

	for (i = 0; i < numProcess; i++) {	//각 process 파일을 가리키는 포인터 설정, procEntry 설정
		procTable[i].tracefp = fopen(argv[i + 3], "r");
		procTable[i].traceName = argv[i + 3];
		procTable[i].ntraces = 0;
		procTable[i].pid = i;
		procTable[i].num2ndLevelPageTable = 0;
		procTable[i].numPageHit = 0;
		procTable[i].numPageFault = 0;
		procTable[i].firstLevelPageTable = (pageTableEntry*)malloc(sizeof(pageTableEntry)*(1 << (firstLevelBits)));
	}

	framePage *framePageEntry = (framePage*)malloc(sizeof(framePage)*nFrame);	// framePageEntry 생성하기

	initPhyMem(framePageEntry, nFrame); //framePageEntry배열 초기화
	unsigned addr;
	unsigned physicalAddress;
	char rw;

	unsigned firstbit;
	unsigned secondbit;
	unsigned tempfirstbit;
	unsigned tempsecondbit;
	unsigned offset;
	int framePageEntryindex = 0;
	int eofindex = 0;

	while (1) {
		for (i = 0; i < numProcess; i++) {
			fscanf(procTable[i].tracefp, "%x %c", &addr, &rw);	////차례로 주소를 받아옴 이때 주소는 16진수
			if (feof(procTable[i].tracefp)) {
				eofindex = 1;
				break;
			}

			procTable[i].ntraces++;
			firstbit = addr >> (VIRTUALADDRBITS - firstLevelBits);
			secondbit = (addr << firstLevelBits) >> (firstLevelBits + PAGESIZEBITS);
			offset = (addr << (VIRTUALADDRBITS - PAGESIZEBITS)) >> (VIRTUALADDRBITS - PAGESIZEBITS);
			procTable[i].firstLevelPageTable[firstbit].level = 1;

			if (procTable[i].firstLevelPageTable[firstbit].valid != 'Y') {	// index firstbit의 valid가 유효하지 않은 경우
				procTable[i].numPageFault++;	// page fault 증가
				procTable[i].num2ndLevelPageTable++;	// secondLevelPageTable 만든 개수 하나증가
				procTable[i].firstLevelPageTable[firstbit].valid = 'Y';	// secondLevelPageTable 만들었다고 표시
				procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable = (pageTableEntry*)malloc(sizeof(pageTableEntry)*(1 << (VIRTUALADDRBITS - PAGESIZEBITS - firstLevelBits)));
				procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].level = 2;	// Level 2 표시

				if (framePageEntryindex >= nFrame) {	//Frame의 개수가 초과하는 경우
					tempfirstbit = oldestFrame->virtualPageNumber >> (VIRTUALADDRBITS - firstLevelBits - PAGESIZEBITS);
					tempsecondbit = ((oldestFrame->virtualPageNumber << (PAGESIZEBITS + firstLevelBits)) >> (firstLevelBits + PAGESIZEBITS));
					procTable[oldestFrame->pid].firstLevelPageTable[tempfirstbit].secondLevelPageTable[tempsecondbit].valid = 'N';
					procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].frameNumber = oldestFrame->number;
					procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].valid = 'Y';
					oldestFrame->pid = procTable[i].pid;
					oldestFrame->virtualPageNumber = addr >> PAGESIZEBITS;
					physicalAddress = (oldestFrame->number << PAGESIZEBITS) + offset;
					printf("2Level procID %d traceNumber %d virtual addr %x pysical addr %x\n", i, procTable[i].ntraces, addr, physicalAddress);
					oldestFrame = oldestFrame->lruRight;
				}

				else {   // frame의 개수가 초과하지 않는 경우 -> 새로운 frame 생성
					procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].valid = 'Y';
					procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].frameNumber = oldestFrame->number;
					oldestFrame->pid = procTable[i].pid;
					oldestFrame->virtualPageNumber = addr >> PAGESIZEBITS;
					physicalAddress = (oldestFrame->number << PAGESIZEBITS) + offset;
					printf("2Level procID %d traceNumber %d virtual addr %x pysical addr %x\n", i, procTable[i].ntraces, addr, physicalAddress);
					oldestFrame = oldestFrame->lruRight;
					framePageEntryindex++;
				}
			}

			else if (procTable[i].firstLevelPageTable[firstbit].valid == 'Y') {	//secondLevelPageTanle이 있으면

				if (procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].valid != 'Y') {	//secondLevelPageTable의 valid 검사	
					procTable[i].numPageFault++;

					if (framePageEntryindex >= nFrame) {	//Frame의 개수가 초과하는 경우
						tempfirstbit = oldestFrame->virtualPageNumber >> VIRTUALADDRBITS - firstLevelBits - PAGESIZEBITS;
						tempsecondbit = (oldestFrame->virtualPageNumber << PAGESIZEBITS + firstLevelBits) >> firstLevelBits + PAGESIZEBITS;
						procTable[oldestFrame->pid].firstLevelPageTable[tempfirstbit].secondLevelPageTable[tempsecondbit].valid = 'N';
						procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].frameNumber = oldestFrame->number;
						procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].valid = 'Y';
						oldestFrame->pid = procTable[i].pid;
						oldestFrame->virtualPageNumber = addr >> PAGESIZEBITS;
						physicalAddress = (oldestFrame->number << PAGESIZEBITS) + offset;
						printf("2Level procID %d traceNumber %d virtual addr %x pysical addr %x\n", i, procTable[i].ntraces, addr, physicalAddress);
						oldestFrame = oldestFrame->lruRight;
					}

					else if (framePageEntryindex < nFrame) {   // frame의 개수가 초과하지 않는 경우
						procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].valid = 'Y';
						procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].frameNumber = oldestFrame->number;
						oldestFrame->pid = procTable[i].pid;
						oldestFrame->virtualPageNumber = addr >> PAGESIZEBITS;
						physicalAddress = (oldestFrame->number << PAGESIZEBITS) + offset;
						printf("2Level procID %d traceNumber %d virtual addr %x pysical addr %x\n", i, procTable[i].ntraces, addr, physicalAddress);
						oldestFrame = oldestFrame->lruRight;
						framePageEntryindex++;
					}
				}

				else if (procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].valid == 'Y') {	// HIT !!!!!

					if (procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].frameNumber == oldestFrame->number) {	//oldsetFrame이 hit인 경우
						procTable[i].numPageHit++;
						oldestFrame = oldestFrame->lruRight;
					}

					else {	//oldsetFrame이 아닌놈이 hit일 경우, oldestFrame왼쪽에다 넣기
						procTable[i].numPageHit++;
						int newnumber = procTable[i].firstLevelPageTable[firstbit].secondLevelPageTable[secondbit].frameNumber;
						framePageEntry[newnumber].lruLeft->lruRight = framePageEntry[newnumber].lruRight;
						framePageEntry[newnumber].lruRight->lruLeft = framePageEntry[newnumber].lruLeft;
						oldestFrame->lruLeft->lruRight = &framePageEntry[newnumber];
						framePageEntry[newnumber].lruLeft = oldestFrame->lruLeft;
						oldestFrame->lruLeft = &framePageEntry[newnumber];
						framePageEntry[newnumber].lruRight = oldestFrame;
						physicalAddress = (oldestFrame->number << PAGESIZEBITS) + offset;
						printf("2Level procID %d traceNumber %d virtual addr %x pysical addr %x\n", i, procTable[i].ntraces, addr, physicalAddress);
					}
				}
			}
		}
		if (eofindex == 1) break;
	}

	secondLevelVMSim(procTable, framePageEntry);
	free(procTable);	// 동적 메모리 삭제
	free(framePageEntry);
	//----------------------------------------------two level paget table 끝 ----------------------------------------
	   // initialize procTable for the inverted Page Table

	framePageEntryindex = 0;
	eofindex = 0;
	int HashTableindex;
	procTable = (procEntry*)malloc(sizeof(procEntry)*numProcess);	// processtableEntry생성
	framePageEntry = (framePage*)malloc(sizeof(framePage)*nFrame);	// framePageEntry 생성하기
	initPhyMem(framePageEntry, nFrame); //framePageEntry배열 초기화
	invertedPageTableEntry *HashTable = (invertedPageTableEntry*)malloc(sizeof(invertedPageTableEntry)*nFrame);	//HashTable 생성
	//(#virtualpage + processid) % #frame가 index
	initHashTable(HashTable, nFrame);	// hashtable 초기화 시켜주기 
	for (i = 0; i < numProcess; i++) {	//각 process 파일을 가리키는 포인터 설정, procEntry 설정
		procTable[i].tracefp = fopen(argv[i + 3], "r");
		procTable[i].traceName = argv[i + 3];
		procTable[i].ntraces = 0;
		procTable[i].pid = i;
		int numIHTConflictAccess = 0;
		int numIHTNULLAccess = 0;
		int numIHTNonNULLAcess = 0;
		procTable[i].numPageHit = 0;
		procTable[i].numPageFault = 0;
		rewind(procTable[i].tracefp);
	}

	struct invertedPageTableEntry *ptr;
	struct invertedPageTableEntry *preptr;

	printf("=============================================================\n");
	printf("The Inverted Page Table Memory Simulation Starts .....\n");
	printf("=============================================================\n");

	while (1) {	//process 시작!!!!!!!!!!!!!!!!!!
		for (i = 0; i < numProcess; i++) {
			fscanf(procTable[i].tracefp, "%x %c", &addr, &rw);	////차례로 주소를 받아옴 이때 주소는 16진수
			if (feof(procTable[i].tracefp)) {
				eofindex = 1;
				break;
			}

			procTable[i].ntraces++;
			firstbit = addr >> (VIRTUALADDRBITS - firstLevelBits);
			secondbit = (addr << firstLevelBits) >> (firstLevelBits + PAGESIZEBITS);
			offset = (addr << (VIRTUALADDRBITS - PAGESIZEBITS)) >> (VIRTUALADDRBITS - PAGESIZEBITS);
			HashTableindex = ((addr >> PAGESIZEBITS) + procTable[i].pid) % nFrame;	//HashTableindex 설정 !!!!!

			if (HashTable[HashTableindex].next == NULL) {	//접근한 해쉬테이블이 기존에 맵핑된 정보가 없다면 !!
				procTable[i].numPageFault++;
				procTable[i].numIHTNULLAccess++;
				invertedPageTableEntry *plusHashTable = (invertedPageTableEntry*)malloc(sizeof(invertedPageTableEntry) * 1);	// mapping 정보 저장 할 테이블 생성
				plusHashTable->next = NULL;
 
				if (framePageEntryindex >= nFrame) {	//Frame의 개수가 초과하는 경우
					preptr = &HashTable[((oldestFrame->virtualPageNumber) + oldestFrame->pid) % nFrame];
					ptr = preptr->next;

					while (1) {
						if (oldestFrame->virtualPageNumber == ptr->virtualPageNumber && oldestFrame->pid == ptr->pid) {
							preptr->next = ptr->next;
							free(ptr);
							break;
						}
						preptr = ptr;
						ptr = ptr->next;
						assert(ptr != NULL);
					}

					oldestFrame->pid = procTable[i].pid;
					oldestFrame->virtualPageNumber = (addr >> PAGESIZEBITS);
					plusHashTable->pid = procTable[i].pid;
					plusHashTable->virtualPageNumber = (addr >> PAGESIZEBITS);
					plusHashTable->frameNumber = oldestFrame->number;
					HashTable[HashTableindex].next = plusHashTable;
					physicalAddress = (oldestFrame->number << PAGESIZEBITS) + offset;
					printf("IHT procID %d traceNumber %d virtual addr %x pysical addr %x\n", i, procTable[i].ntraces, addr, physicalAddress);
					oldestFrame = oldestFrame->lruRight;
				}

				else {   // frame의 개수가 초과하지 않는 경우 -> 새로운 frame 생성
					oldestFrame->pid = procTable[i].pid;
					oldestFrame->virtualPageNumber = (addr >> PAGESIZEBITS);
					plusHashTable->pid = procTable[i].pid;
					plusHashTable->virtualPageNumber = (addr >> PAGESIZEBITS);
					plusHashTable->frameNumber = oldestFrame->number;
					HashTable[HashTableindex].next = plusHashTable;
					physicalAddress = (oldestFrame->number << PAGESIZEBITS) + offset;
					printf("IHT procID %d traceNumber %d virtual addr %x pysical addr %x\n", i, procTable[i].ntraces, addr, physicalAddress);
					oldestFrame = oldestFrame->lruRight;
					framePageEntryindex++;
				}
			}

			else if (HashTable[HashTableindex].next != NULL) {	//접근한 해쉬테이블에 기존에 맵핑된 정보가 있다면 ?!
				procTable[i].numIHTNonNULLAcess++;
				preptr = &HashTable[HashTableindex];
				ptr = preptr->next;
				while (1) {	// ptr, preptr 추적 !!!
					procTable[i].numIHTConflictAccess++;

					if (ptr == NULL) {		// next를 따라 가봤지만 mapping된 정보중에 hit가 없을때 
						procTable[i].numPageFault++;
						invertedPageTableEntry *plusHashTable = (invertedPageTableEntry*)malloc(sizeof(invertedPageTableEntry) * 1);	// mapping 정보 저장 할 테이블 생성
						plusHashTable->next = NULL;

						if (framePageEntryindex >= nFrame) {	//Frame의 개수가 초과하는 경우
							preptr = &HashTable[((oldestFrame->virtualPageNumber) + oldestFrame->pid) % nFrame];
							ptr = preptr->next;

							while (1) {		// oldestFrame에 저장되어 있던 HashTable의 정보를 찾아가서 지우기
								if (oldestFrame->virtualPageNumber == ptr->virtualPageNumber && oldestFrame->pid == ptr->pid) {
									preptr->next = ptr->next;
									free(ptr);
									break;
								}

								preptr = ptr;
								ptr = ptr->next;
								assert(ptr != NULL);		// oldestFrame에 저장되어 있던 HashTable에 그 정보가 없으면 에러
							}

							plusHashTable->next = HashTable[HashTableindex].next;
							HashTable[HashTableindex].next = plusHashTable;
							oldestFrame->pid = procTable[i].pid;
							oldestFrame->virtualPageNumber = (addr >> PAGESIZEBITS);
							plusHashTable->pid = procTable[i].pid;
							plusHashTable->virtualPageNumber = (addr >> PAGESIZEBITS);
							plusHashTable->frameNumber = oldestFrame->number;
							physicalAddress = (oldestFrame->number << PAGESIZEBITS) + offset;
							printf("IHT procID %d traceNumber %d virtual addr %x pysical addr %x\n", i, procTable[i].ntraces, addr, physicalAddress);
							oldestFrame = oldestFrame->lruRight;
						}

						else {   // frame의 개수가 초과하지 않는 경우 -> 새로운 frame 생성
							plusHashTable->next = HashTable[HashTableindex].next;
							HashTable[HashTableindex].next = plusHashTable;
							oldestFrame->pid = procTable[i].pid;
							oldestFrame->virtualPageNumber = (addr >> PAGESIZEBITS);
							plusHashTable->pid = procTable[i].pid;
							plusHashTable->virtualPageNumber = addr >> PAGESIZEBITS;
							plusHashTable->frameNumber = oldestFrame->number;
							physicalAddress = (oldestFrame->number << PAGESIZEBITS) + offset;
							printf("IHT procID %d traceNumber %d virtual addr %x pysical addr %x\n", i, procTable[i].ntraces, addr, physicalAddress);
							oldestFrame = oldestFrame->lruRight;
							framePageEntryindex++;
						}

						procTable[i].numIHTConflictAccess--;
						break;
					}

					else if ((ptr->pid == procTable[i].pid) && (ptr->virtualPageNumber == (addr >> PAGESIZEBITS))) {	//	next를따라 가보았는데 mapping된 정보가 있다 !!
						procTable[i].numPageHit++;

						if (ptr->frameNumber == oldestFrame->number) {	//oldsetFrame이 hit인 경우	
							oldestFrame = oldestFrame->lruRight;
							physicalAddress = (oldestFrame->number << PAGESIZEBITS) + offset;
							printf("IHT procID %d traceNumber %d virtual addr %x pysical addr %x\n", i, procTable[i].ntraces, addr, physicalAddress);
							break;
						}

						else {	//oldestFrame이 아닌게 hit인 경우
							int newnumber = ptr->frameNumber;
							framePageEntry[newnumber].lruLeft->lruRight = framePageEntry[newnumber].lruRight;
							framePageEntry[newnumber].lruRight->lruLeft = framePageEntry[newnumber].lruLeft;
							oldestFrame->lruLeft->lruRight = &framePageEntry[newnumber];
							framePageEntry[newnumber].lruLeft = oldestFrame->lruLeft;
							oldestFrame->lruLeft = &framePageEntry[newnumber];
							framePageEntry[newnumber].lruRight = oldestFrame;
							physicalAddress = (oldestFrame->number << PAGESIZEBITS) + offset;
							printf("IHT procID %d traceNumber %d virtual addr %x pysical addr %x\n", i, procTable[i].ntraces, addr, physicalAddress);
							break;
						}
					}
					preptr = ptr;
					ptr = ptr->next;
				}
			}
		} // numprocess for문
		if (eofindex == 1) break;
	}	//while문
	invertedPageVMSim(procTable, framePageEntry, nFrame);
	return(0);
}
