/*
 * mm-implicit.c - an empty malloc package
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 *
 * @id : 201902748 
 * @name : 전해준
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
#define DEBUG
#ifdef DEBUG
# define dbg_printf(...) printf(__VA_ARGS__)
#else
# define dbg_printf(...)
#endif

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)

#define WSIZE 4
#define DSIZE 8
#define CHUNKSIZE (1<<12)
#define OVERHEAD 8
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define PACK(size, alloc) ((size) | (alloc))
#define GET(p) (*(unsigned int*)(p))
#define PUT(p, val) (*(unsigned int*)(p) = (val))
#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)
#define HDRP(bp) ((char*)(bp) - WSIZE)
#define FTRP(bp) ((char*)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)
#define NEXT_BLKP(bp) ((char*)(bp) + GET_SIZE(((char*)(bp) - WSIZE)))
#define PREV_BLKP(bp) ((char*)(bp) - GET_SIZE(((char*)(bp) - DSIZE)))

static char *heap_listp = 0;
static char *next_listp = 0;

static void *coalesce(void *bp) {
	size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
	// 이전 블럭의 할당 여부 0 = NO, 1 = YES
	size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
	// 다음 블럭의 할당 여부 0 = NO, 1 = YES
	size_t size = GET_SIZE(HDRP(bp));
	// 현재 블럭의 크기

	/*
	 * case 1 : 이전 블럭, 다음 블럭 최하위 bit가 둘 다 1인 경우 (할당)
	 * 			블럭 병합 없이 bp return
	 */
	if(prev_alloc && next_alloc) return bp;

	/*
	 * case 2 : 이전 블럭 최하위 bit가 1이고 (할당), 다음 블럭 최하위 bit가 0인 경우 (비할당)
	 * 			다음 블럭과 병합한 뒤 bp return
	 */
	else if(prev_alloc && !next_alloc) {
		size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
		PUT(HDRP(bp), PACK(size, 0));
		PUT(FTRP(bp), PACK(size, 0));
	}

	/*
	 * case 3 : 이전 블럭 최하위 bit가 0이고 (비할당), 다음 블럭 최하위 bit가 1인경우 (할당)
	 * 			이전 블럭과 병합한 뒤 새로운 bp return
	 */
	else if(!prev_alloc && next_alloc) {
		size += GET_SIZE(HDRP(PREV_BLKP(bp)));
		PUT(FTRP(bp), PACK(size, 0));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
		bp = PREV_BLKP(bp);
	}

	/*
	 * case 4 : 이전 블럭 최하위 bit가 0이고 (비할당), 다음 블럭 최하위 bit가 0인경우 (비할당)
	 * 			이전 블럭, 현재 블럭, 다음 블럭을 모두 병합한 뒤 새로운 bp return
	 */
	else {
		size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(FTRP(NEXT_BLKP(bp)));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
		PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
		bp = PREV_BLKP(bp);
	}
	next_listp=bp;
	return bp;	// 병합된 블럭의 주소 bp return
}

static void *extend_heap(size_t words) {
	void *bp;
	size_t size;

	size = (words%2) ? (words+1)*WSIZE : words*WSIZE;
	if((long)(bp=mem_sbrk(size)) == -1) return NULL;

	PUT(HDRP(bp), PACK(size, 0));
	PUT(FTRP(bp), PACK(size, 0));
	PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));

	return coalesce(bp);
}

static void place(void *bp, size_t asize) {
	size_t current_size = GET_SIZE(HDRP(bp));

	if((current_size-asize) >= (2*DSIZE)) {
		PUT(HDRP(bp), PACK(asize, 1));
		PUT(FTRP(bp), PACK(asize, 1));
		bp = NEXT_BLKP(bp);
		PUT(HDRP(bp), PACK(current_size-asize, 0));
		PUT(FTRP(bp), PACK(current_size-asize, 0));
	}
	else {
		PUT(HDRP(bp), PACK(current_size, 1));
		PUT(FTRP(bp), PACK(current_size, 1));
	}
}

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {   
	if((heap_listp = mem_sbrk(4*WSIZE)) == NULL) // 초기 empty heap 생성
		return -1;							 	 // heap_listp = 새로 생성되는 heap 영역의 시작 주소

	PUT(heap_listp, 0);							 // heap의 시작부분 할당
	PUT(heap_listp+WSIZE, PACK(OVERHEAD, 1));	 // prologue header
	PUT(heap_listp+DSIZE, PACK(OVERHEAD, 1));	 // prologue footer
	PUT(heap_listp+WSIZE+DSIZE, PACK(0, 1));	 // epilogue header
	heap_listp += DSIZE;
	next_listp = heap_listp;

	if(extend_heap(CHUNKSIZE/WSIZE) == NULL)	 // CHUNKSIZE 바이트의 free block을 생성
		return -1;
	return 0;
}

static void *find_fit(size_t asize) {
	void *bp;
	for(bp=next_listp; GET_SIZE(HDRP(bp))>0; bp=NEXT_BLKP(bp)) {
		if(!GET_ALLOC(HDRP(bp)) && (asize<=GET_SIZE(HDRP(bp)))) {
			next_listp = bp;
			return bp;
		}
	}

	for(bp=heap_listp; bp<(void*)next_listp; bp=NEXT_BLKP(bp)) {
		if(!GET_ALLOC(HDRP(bp)) && (asize<=GET_SIZE(HDRP(bp)))){
			next_listp = bp;
			return bp;
		}
	}

	/*	first-fit 구현 시 (64/100)
		for(bp=heap_listp; GET_SIZE(HDRP(bp))>0; bp=NEXT_BLKP(bp)) {
			if(!GET_ALLOC(HDRP(bp)) && (asize<=GET_SIZE(HDRP(bp)))) return bp;
		}
	*/
	return NULL;
}

/*
 * malloc
 */
void *malloc (size_t size) {
    size_t asize;
	size_t extendsize;
	char *bp;

	if(heap_listp==0) mm_init();
	if(size==0) return NULL;
	if(size <= DSIZE)  // 할당한 크기가 DSIZE 보다 작은 경우, align을 위해 블록 크기를 DSIZE + OVERHEAD로 설정
		asize =	DSIZE+OVERHEAD;
	else asize = DSIZE+ALIGN(size); // 그 이외의 경우는 적당하게 align을 맞춰 블록크기 설정

	if((bp=find_fit(asize))!=NULL) {	// find_fit 함수로 적당한 블록 탐색
		place(bp, asize);	// 위에서 찾은 block에 가용블록 표시 및, 사이즈 표시
		return bp;
	}
	
	extendsize = MAX(asize, CHUNKSIZE);
	if((bp=extend_heap(extendsize/WSIZE))==NULL) return NULL;
	place(bp, asize);
	return bp;
}

/*
 * free
 */
void free (void *bp) {
    if(bp<=0) return;
	size_t size = GET_SIZE(HDRP(bp)); //ptr의 헤더에서 block size를 읽어온다
	
	//실제로 데이터를 지우는 것이 아닌,
	//header와 footer의 최하위 1bit(1, 할당된 상태)를 수정하여 간단하게 free가 가능
	PUT(HDRP(bp), PACK(size, 0));	//ptr의 header에 block size와 alloc = 0을 저장
	PUT(FTRP(bp), PACK(size, 0));	//ptr의 footer에 block size와 alloc = 0을 저장
	coalesce(bp);
}

/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *oldptr, size_t size) {
	void *newptr;
	size_t copysize;

	if(size==0) {
		free(oldptr);
		return 0;
	}
	if(oldptr==NULL) return malloc(size);

	if((newptr = malloc(size)) == NULL) return NULL;
	if(size < (copysize = GET_SIZE(HDRP(oldptr)) - OVERHEAD)) copysize=size;
	memcpy(newptr, oldptr, copysize);
	free(oldptr);
	return newptr;
}

/*
 * calloc - you may want to look at mm-naive.c
 * This function is not tested by mdriver, but it is
 * needed to run the traces.
 */
void *calloc (size_t nmemb, size_t size) {
    return NULL;
}

/*
 * Return whether the pointer is in the heap.
 * May be useful for debugging.
 */
static int in_heap(const void *p) {
    return p < mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Return whether the pointer is aligned.
 * May be useful for debugging.
 */
static int aligned(const void *p) {
    return (size_t)ALIGN(p) == (size_t)p;
}

/*
 * mm_checkheap
 */
void mm_checkheap(int verbose) {
}
