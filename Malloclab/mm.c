/*
 * mm-explicit.c - an empty malloc package
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

/* Basic constants and macros */
#define HDRSIZE 	4	 /* header size (bytes) */
#define FTRSIZE 	4	 /* footer size (bytes) */
#define WSIZE 		4	 /* word size (bytes) */
#define DSIZE 		8	 /* doubleword size (bytes) */
#define CHUNKSIZE 	(1<<12)	/* initial heap size (bytes) */
#define OVERHEAD	8	 /* overhead of header and footer (bytes) */

#define MAX(x,y) ((x) > (y)? (x) : (y))
#define MIN(x,y) ((x) < (y)? (x) : (y))

/* Pack a size and allocated bit into a word */
#define PACK(size, alloc) 	((unsigned)((size) | (alloc)))

/* Read and write a word at address p */
#define GET(p)			(*(unsigned *)(p))
#define PUT(p, val) 	(*(unsigned *)(p) = (unsigned)(val))
#define GET8(p)			(*(unsigned long *)(p))
#define PUT8(p, val) 	(*(unsigned long *)(p) = (unsigned long)(val))

/* Read the size and allocated fields from address p */
#define GET_SIZE(p)		(GET(p) & ~0x7)
#define GET_ALLOC(p)	(GET(p)	& 0x1)

/* Given block ptr bp, compute address of its header and footer */
#define HDRP(bp)		((char *)(bp) - WSIZE)
#define FTRP(bp)		((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

/* Given block ptr bp, compute address of next and previous blocks */
#define NEXT_FREEP(bp)	((char*)(bp))
#define PREV_FREEP(bp)	((char*)(bp) + DSIZE)

/* Given free block pointer bp, compute address of next and previous free blocks */
#define NEXT_FREE_BLKP(bp)	((char*)GET8((char*)(bp)))
#define PREV_FREE_BLKP(bp)	((char*)GET8((char*)(bp) + DSIZE))

/* Given free block pointer bp, compute address of next pointer and prev pointer */
#define NEXT_BLKP(bp)	((char*)(bp) + GET_SIZE((char*)(bp) - WSIZE))
#define PREV_BLKP(bp)	((char*)(bp) - GET_SIZE((char*)(bp) - DSIZE))

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)

void *extend_heap(size_t);
void *find_fit(size_t);
void *coalesce(void*);
void place(void*, size_t);
static void insert_free_block(void*);
static void remove_free_block(void*);

void *h_ptr = NULL;
void *heap_start = NULL;

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
	/* Request memory for the initial empty heap */
	if ((h_ptr = mem_sbrk(DSIZE + 4*HDRSIZE)) == NULL) return -1;
	heap_start = h_ptr;

	PUT8(h_ptr, NULL);				
	PUT8(h_ptr + WSIZE, NULL);
	PUT(h_ptr + DSIZE, 0);                          			// alignment padding
	PUT(h_ptr + DSIZE + HDRSIZE, PACK(OVERHEAD,1));  			// prologue header
	PUT(h_ptr + DSIZE + HDRSIZE + FTRSIZE, PACK(OVERHEAD,1));  	// prologue footer  

	/* Move heap pointer over to footer */
	h_ptr += 2*DSIZE;

	/* Extend the empty heap with a free block of CHUNKSIZE bytes */
	if(extend_heap(CHUNKSIZE/WSIZE) == NULL) return -1;
  	return 0;
}

/*
 * malloc
 */
void *malloc (size_t size) {
  	char *bp;				// Block pointer, points to first byte of payload
	unsigned asize;			// Block size adjusted for alignment and overhead
	unsigned extendsize; 	// Amount to extend heap if no fit

	// size가 올바르지 않을 때 예외처리
	if(h_ptr==0) mm_init();
	if(size<=0) return NULL;

	// block 크기 결정
	if(size<=2*DSIZE) asize = 2*DSIZE+OVERHEAD;
	else asize = DSIZE+ALIGN(size);

	// 결정한 크기에 알맞은 블록을 list에서 검색하여 해당 위치에 할당
	if((bp = find_fit(asize)) != NULL) {
		place(bp, asize);
		return bp;
	}

	// free list에서 적절한 블록을 찾지 못했으면 힙을 늘려서 할당
	extendsize = MAX(asize, CHUNKSIZE);
	if ((bp = extend_heap(extendsize/WSIZE)) == NULL) return NULL;

	place(bp, asize);
	return bp;
}

/*
 * free
 */
void free (void *ptr) {
    if(ptr <= 0) return;
	size_t size = GET_SIZE(HDRP(ptr));

	PUT(HDRP(ptr), PACK(size,0));
	PUT(FTRP(ptr), PACK(size,0));
	
	coalesce(ptr);
}

/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *oldptr, size_t size) {
	size_t oldsize;
	void *newptr;

	if(oldptr==NULL) return malloc(size);
	else if(size==0) {
		free(oldptr);
		return NULL;
	}

	oldsize = GET_SIZE(HDRP(oldptr)) - OVERHEAD;
	if(size<=oldsize) return oldptr;
	else {
		newptr=malloc(size);
		memcpy(newptr, oldptr, size);
		free(oldptr);
		return newptr;
	}

	return NULL;
}

/*
 * extend_heap
 */
void *extend_heap(size_t words) {
	char *bp;					// New block pointer after heap extension
	unsigned size;				// Request size for heap memory

	/* Allocate an even number of words to maintain alignment */
	size = (words%2) ? (words+1)*DSIZE : words*DSIZE;

	/* Request more memory from heap */
	if((long)(bp = mem_sbrk(size)) < 0)	return NULL;

	/* Write in the header, footer and new epilogue*/
	PUT(HDRP(bp), PACK(size,0));
	PUT(FTRP(bp), PACK(size,0));
	PUT(HDRP(NEXT_BLKP(bp)), PACK(0,1));

	return coalesce(bp);
}

void place(void *bp, size_t asize) {
	size_t current_size = GET_SIZE(HDRP(bp));
	remove_free_block(bp);

	if(current_size-asize >= OVERHEAD + 2*DSIZE) {
		PUT(HDRP(bp), PACK(asize,1));
		PUT(FTRP(bp), PACK(asize,1));
		PUT(HDRP(NEXT_BLKP(bp)), PACK(current_size-asize,0));
		PUT(FTRP(NEXT_BLKP(bp)), PACK(current_size-asize,0));

		insert_free_block((void*)NEXT_BLKP(bp));
	}
	else {
		PUT(HDRP(bp), PACK(current_size,1));
		PUT(FTRP(bp), PACK(current_size,1));
	}
}

void *find_fit(size_t asize) {
	void *bp;
	 
	for(bp=(void*)GET8(heap_start); bp!=NULL; bp=(void*)NEXT_FREE_BLKP(bp)) {
		if(asize<=GET_SIZE(HDRP(bp))) return bp;
	}

	return NULL;
}

void *coalesce(void *bp) {
	size_t prev_alloc = GET_ALLOC(HDRP(bp) - FTRSIZE);
	size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
	size_t size = GET_SIZE(HDRP(bp));
	if(prev_alloc && !next_alloc) {
		size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
		remove_free_block(NEXT_BLKP(bp));
		PUT(HDRP(bp), PACK(size,0));
		PUT(FTRP(bp), PACK(size,0));
	} else if(!prev_alloc && next_alloc) {
		size += GET_SIZE(HDRP(PREV_BLKP(bp)));
		remove_free_block(PREV_BLKP(bp));
		PUT(FTRP(bp), PACK(size,0));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size,0));
		bp = PREV_BLKP(bp);
	} else if(!prev_alloc && !next_alloc) {
		size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(FTRP(NEXT_BLKP(bp)));
		remove_free_block(NEXT_BLKP(bp));
		remove_free_block(PREV_BLKP(bp));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size,0));
		PUT(FTRP(NEXT_BLKP(bp)), PACK(size,0));
		bp = PREV_BLKP(bp);
	}
	insert_free_block(bp);
	return bp;
}

static void insert_free_block(void *bp) {
	if((void *)GET8(heap_start) != NULL) {
		PUT8(NEXT_FREEP((void *)GET8((heap_start + DSIZE))), bp);
		PUT8(PREV_FREEP(bp), (void *)GET8((heap_start + DSIZE)));
	} else {
		PUT8((char *)heap_start, bp);
		PUT8(PREV_FREEP(bp), NULL);
	}

	PUT8(NEXT_FREEP(bp), NULL);
	PUT8(((char *)heap_start + DSIZE), bp);

	return;
}

static void remove_free_block(void *bp) {
	if ((void*)NEXT_FREE_BLKP(bp) == NULL) {
		if ((void*)PREV_FREE_BLKP(bp) == NULL) {
			PUT8((char *)heap_start, NULL);
			PUT8(((char *)heap_start + DSIZE), NULL);
			return;
		}
		PUT8(NEXT_FREEP(PREV_FREE_BLKP(bp)), NULL);
		PUT8(((char *)heap_start + DSIZE), PREV_FREE_BLKP(bp));
	}
	else if ((void*)PREV_FREE_BLKP(bp) == NULL) {
		PUT8((char *)heap_start, NEXT_FREE_BLKP(bp));
		PUT8(PREV_FREEP((void *)GET8(heap_start)), NULL);
	}
	else {
		PUT8(PREV_FREEP(NEXT_FREE_BLKP(bp)), PREV_FREE_BLKP(bp));
		PUT8(NEXT_FREEP(PREV_FREE_BLKP(bp)), NEXT_FREE_BLKP(bp));
	}
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
