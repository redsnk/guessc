#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#ifdef USE_OPENSSL
#include <openssl/evp.h>
#endif

#define MY_VERSION	"v0.7"
#define TRUE		(-1)
#define FALSE		(0)
#define MAX_STR		(1024)
#define MIN_STR		(64)
#define BASE 		"%s/src/pwnedpasswords/%s"
#define ALPHA		"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!\"·$%&/()='?¡¿<>,;.:-_+* |@#~[]^\\"
#define ALPHA_MIN	"abcdefghijklmnopqrstuvwxyz0123456789"
#define MAX_DEEP	0
#define SHA1_LEN	20
#define TAIL_BYTES	8		// max 18 bytes, 60 bits is enough to avoid collisions, much less memory and a little faster.
#define LOG		"guessc.txt"
#define MAX_MEMORY 	(1024L*1024L*1024L*8L)
#define FORCE_DEEP	4
#define MAX_THREADS	4
#define MEM_INSERT	(1024*1024*10)
#define PRECACHE
#define DISPLAY_MS	500
#define THREADS_CACHE	32

long long max_memory = MAX_MEMORY;
int llog = TRUE;
int max_deep = MAX_DEEP;
int deep_min = FALSE;
int max_threads = MAX_THREADS;
long long recovered = 0;
long long d_recovered = 0;
struct timeval oldtime;

#ifndef USE_OPENSSL
// https://www.nayuki.io/page/fast-sha1-hash-implementation-in-x86-assembly

#define BLOCK_LEN 64  // In bytes
#define STATE_LEN 5  // In words

extern void sha1_compress(const uint8_t block[static BLOCK_LEN], uint32_t state[static STATE_LEN]);

void sha1_hash(const uint8_t message[], size_t len, uint32_t hash[static STATE_LEN]) {
	hash[0] = UINT32_C(0x67452301);
	hash[1] = UINT32_C(0xEFCDAB89);
	hash[2] = UINT32_C(0x98BADCFE);
	hash[3] = UINT32_C(0x10325476);
	hash[4] = UINT32_C(0xC3D2E1F0);

	#define LENGTH_SIZE 8  // In bytes

	size_t off;
	for (off = 0; len - off >= BLOCK_LEN; off += BLOCK_LEN)
		sha1_compress(&message[off], hash);

	uint8_t block[BLOCK_LEN] = {0};
	size_t rem = len - off;
	if (rem > 0)
		memcpy(block, &message[off], rem);

	block[rem] = 0x80;
	rem++;
	if (BLOCK_LEN - rem < LENGTH_SIZE) {
		sha1_compress(block, hash);
		memset(block, 0, sizeof(block));
	}

	block[BLOCK_LEN - 1] = (uint8_t)((len & 0x1FU) << 3);
	len >>= 5;
	for (int i = 1; i < LENGTH_SIZE; i++, len >>= 8)
		block[BLOCK_LEN - 1 - i] = (uint8_t)(len & 0xFFU);
	sha1_compress(block, hash);

	#undef LENGTH_SIZE
}

unsigned int sha1(char *text,unsigned char *md_value) {
uint32_t hash[STATE_LEN];
int i;

	sha1_hash(text,strlen(text),hash);
	for (i=0;i<STATE_LEN;i++) {
		md_value[0+(i*4)] = hash[i] >> 24;
		md_value[1+(i*4)] = (hash[i] >> 16) & 0xff;
		md_value[2+(i*4)] = (hash[i] >> 8) & 0xff;
		md_value[3+(i*4)] = hash[i] & 0xff;
	}
}
#endif
//
struct entry {
	unsigned char h[TAIL_BYTES];
};

struct entries {
	short int num;
	struct entry e[1];
};

#define ENTRIES	0x100000

struct index {
	struct entries *i[ENTRIES];
};

struct info_cache_entry {
	unsigned char free;
	pthread_t thread;
	unsigned char join;
};

//unsigned char free_cache[THREADS_CACHE];

struct info_cache_entry info_cache[THREADS_CACHE];

struct index idx;


pthread_mutex_t mutex_memory_counter = PTHREAD_MUTEX_INITIALIZER;
unsigned long long memory = 0L;
long long count = 0L;

void set_memory_counter(unsigned long long n,long long c) {
    pthread_mutex_lock (&mutex_memory_counter);
    memory = n;
    count = c;
    pthread_mutex_unlock (&mutex_memory_counter);
}

unsigned long long get_memory_counter() {
unsigned long long n;

    pthread_mutex_lock (&mutex_memory_counter);
    n = memory;
    pthread_mutex_unlock (&mutex_memory_counter);
    return(n);
}

void add_memory_counter(unsigned long long n, long long c) {
    pthread_mutex_lock (&mutex_memory_counter);
    memory += n;
    count += c;
    printf("Memory: %lliM Passwords: %lli\r",memory/(1024L*1024L),count);
    fflush(stdout);
    pthread_mutex_unlock (&mutex_memory_counter);
}

void panic(char *txt) {
    printf("PANIC: %s\n",txt);
    exit(1);
}

void init_cache(void) {
int n;

    for (n=0;n<ENTRIES;n++) {
	idx.i[n] = NULL;
    }
    for (n=0;n<THREADS_CACHE;n++) {
	info_cache[n].free = TRUE;
	info_cache[n].join = FALSE;
    }
}

void print_entry (struct entry *e) {
int n;

    printf("entry: ");
    for(n=0;n<TAIL_BYTES;n++) {
        printf("%02X",e->h[n]);
    }
    printf("\n");
}

void print_entries (struct entries *ei) {
int n;

    printf("entries:\n");
    printf("--------\n");
    for (n=0;n<ei->num;n++) {
	print_entry(&ei->e[n]);
    }
    printf("--------\n");
}

/*
0000bfd0: 4231 4130 4431 4144 3945 3930 4345 3432  B1A0D1AD9E90CE42
0000bfe0: 3130 3a31 0d0a 4646 4634 4438 4134 4445  10:1..FFF4D8A4DE
0000bff0: 3341 4439 4236 3946 4532 4638 3243 4645  3AD9B69FE2F82CFE
0000c000: 4342 4643 3046 3838 413a 310d 0a46 4646  CBFC0F88A:1..FFF
0000c010: 3543 3441 3438 3642 3532 3844 4438 3444  5C4A486B528DD84D
0000c020: 3146 3144 3346 3431 4130 3645 3932 3536  1F1D3F41A06E9256
0000c030: 3a33                                     :3
*/

static inline unsigned char hex_to_num(char c) {
unsigned char n;

    if ((c>='0') && (c<='9')) {
	return (c-'0');
    }
    if ((c>='A') && (c<='F')) {
	return (c-'A'+10);
    }
    panic("hex_to_num error.");
}

static inline unsigned char hex_to_byte(char *txt) {
unsigned char c;

    c = (hex_to_num(txt[0]) << 4) + hex_to_num(txt[1]);
    return (c);
}

static inline int hex_to_bytes(char *txt,char *b,int len) {
int i=0,n;
char *p;

    p = txt;
    for (n=0;n<len;n++) {
	b[i++] = hex_to_byte(p);
	p += 2;
    }
    return (i);
}

void tail_to_entry(char *txt,struct entry *e) {
char *p;
char buffer[MAX_STR];

    //printf("%s\n",txt);
    p = strchr(txt,':');
    if (p != NULL) {
	*p = 0;
    }
    strcpy(buffer,"0");
    strcat(buffer,txt);
    hex_to_bytes(buffer,e->h,TAIL_BYTES);
    //print_entry(e);
}

static inline unsigned long get_value_entry (struct entry *e) {
	return (*((unsigned long *)e));
}

int cmp_entry (struct entry *e1,struct entry *e2) {
int n;

    for (n=0;n<TAIL_BYTES;n++) {
	if (e1->h[n] != e2->h[n]) {
		return (FALSE);
	}
    }
    return (TRUE);
}

int get_entry_pos (struct entries *en,struct entry *ei) {
int t,b,m,s;
unsigned long v,vm;

    v = get_value_entry(ei);
    t = -1;
    b = en->num;
    while ((b-t)>1) {
        m = t+((b-t)/2);
        vm = get_value_entry(&en->e[m]);
        if (vm > v) {
                b = m;
        }
        else if (vm < v) {
                t = m;
        }
        else {
                // match
                return (m);
        }
    }
    return (b);
}

int find_tail_entries (struct entry *tail,struct entries *en) {
int t,b,m,s;
struct entry *ei;
unsigned long v,vm;

    ei = tail;
    v = get_value_entry(ei);
    t = -1;
    b = en->num;
    while ((b-t)>1) {
	m = t+((b-t)/2);
	vm = get_value_entry(&en->e[m]);
	if (vm > v) {
		b = m;
	}
	else if (vm < v) {
		t = m;
	}
	else {
		// match?
		if (TAIL_BYTES == 8) return (TRUE);	// length value == TAIL_BYTES
		s = m;
		do {
			if (cmp_entry(ei,&en->e[s])) {
				return (TRUE);
			}
			s++;
		}
		while ((s<b) && (v==get_value_entry(&en->e[s])));
		s = m-1;
		while ((s>t) && (v==get_value_entry(&en->e[s]))) {
			if (cmp_entry(ei,&en->e[s])) {
				return (TRUE);
			}
			s--;
		}
		break;
	}
    }
    return (FALSE);
}

char mem[THREADS_CACHE][MEM_INSERT];

void insert_entry (struct entries *en,struct entry *ei,int num_thread) {
int p,n,s;

    if (!en->num) {
	en->e[en->num++] = *ei;
    }
    else {
	p = get_entry_pos (en,ei);
	if (p == en->num) {
		en->e[en->num++] = *ei;
	}
	else {
		n = en->num-p;
		s = n*sizeof(struct entry);
		memcpy(mem[num_thread],&en->e[p],s);
		en->e[p] = *ei;
		memcpy(&en->e[p+1],mem[num_thread],s);
		en->num++;
	}
    }
}

struct entries *txt_to_entries(char *txt,int len,int num_thread) {
struct entries *en;
char *p,*t;
struct entry ei;

    en = malloc(len);
    en->num = 0;
    t = txt;
    while ((p=strchr(t,'\r')) != NULL) {
	p[0] = 0;
	//printf("%s\n",t);
	tail_to_entry(t,&ei);
	//print_entry(&ei);
	t = p+2;
	/*
	en->e[en->num++] = ei;
	sort_last_entry(en);
	*/
	insert_entry(en,&ei,num_thread);
    }
    en = realloc(en,sizeof(struct entries)+(sizeof(struct entry)*(en->num-1)));
    return (en);
}

int add_cache_entries (int head,struct entries *e) {
//int n;
unsigned long long m;

    m = get_memory_counter();
    if (m < max_memory) {
    	//n = head_to_index(head);
    	if (idx.i[head] == NULL) {
		idx.i[head] = e;
		//memory += sizeof(struct entries)+(sizeof(struct entry)*(e->num-1));
		add_memory_counter(sizeof(struct entries)+(sizeof(struct entry)*(e->num-1)),e->num);
        	return (TRUE);
    	}
    }
    free(e);
    return (FALSE);
}

static inline struct entries *get_entries_cache (int head) {
/*
int n;

    n = head_to_index(head);
*/
    return (idx.i[head]);
}

#ifdef USE_OPENSSL
unsigned int sha1(char *text,unsigned char *md_value) {
EVP_MD_CTX *mdctx;
const EVP_MD *md;
unsigned int md_len;

    md = EVP_sha1();
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, text, strlen(text));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);
    EVP_cleanup();
    return (md_len);
}
#endif

void sha1_to_string (unsigned char *md_value,char *buffer) {
char tmp[MAX_STR];

    buffer[0] = 0;
    for(int i = 0; i < SHA1_LEN; i++) {
	sprintf(tmp,"%02X", md_value[i]);
	strcat(buffer,tmp);
    }
}

struct entries *get_entries_disk (int head,int num_thread) {
struct entries *e;
char buffer[MAX_STR];
char s_head[MIN_STR];
long l,ll;
char *p;
FILE *f;

    sprintf(s_head,"%05X",head);
    sprintf (buffer,BASE,getenv("HOME"),s_head);
    //printf("file: %s\n",buffer);
    f = fopen(buffer, "r");
    if (f != NULL) {
        fseek(f,0L,SEEK_END);
        l = ftell(f);
        fseek(f,0L,SEEK_SET);
        p = malloc(l+3);                        // add 3 bytes
        ll = fread (p, sizeof(char),l,f);
        if (l != ll) {
                panic("Error: fread");
        }
	if (ll > MEM_INSERT) {
		panic("Error: MEM_INSERT");
	}
	fclose(f);
        // add '0d0a00' at the end
        p[l] = '\r';
        p[l+1] = '\n';
        p[l+2] = 0;
        e = txt_to_entries(p,l,num_thread);
        free(p);
        //print_entries(e);
        //printf("%li\n",l);
    }
    else {
	printf("name: %s\n",buffer);
	panic("get_entries_disk fopen.");
    }
    return (e);
}

pthread_mutex_t mutex_cache = PTHREAD_MUTEX_INITIALIZER;

//pthread_t c_threads[THREADS_CACHE];

int acquire_thread_cache(void) {
int n;

    pthread_mutex_lock (&mutex_cache);
    for (n=0;n<THREADS_CACHE;n++) {
	if (info_cache[n].free && !info_cache[n].join) {
		info_cache[n].free = FALSE;
		//printf("lock %i\n",n);
		break;
	}
    }
    pthread_mutex_unlock (&mutex_cache);
    if (n<THREADS_CACHE) {
	return (n);
    }
    return (-1);
}

void free_thread_cache (int n) {
    //printf("pre-unlock %i\n",n);
    pthread_mutex_lock (&mutex_cache);
    info_cache[n].free = TRUE;
    info_cache[n].join = TRUE;
    //printf("unlock %i\n",n);
    pthread_mutex_unlock (&mutex_cache);
}

int get_threads_cache_busy(void) {
int n,c;

    c = 0;
    pthread_mutex_lock (&mutex_cache);
    for (n=0;n<THREADS_CACHE;n++) {
        if (!info_cache[n].free) {
		c++;
        }
    }
    pthread_mutex_unlock (&mutex_cache);
    return (c);
}

int get_next_join_cache (int *num,pthread_t *thread) {
int n;

    pthread_mutex_lock (&mutex_cache);
    for (n=0;n<THREADS_CACHE;n++) {
	if (info_cache[n].join) {
		*thread = info_cache[n].thread;
		*num = n;
		info_cache[n].join = FALSE;
		break;
	}
    }
    pthread_mutex_unlock (&mutex_cache);
    return (n<THREADS_CACHE);
}

void dispatch_joins_cache (void) {
pthread_t thread;
int num;

    while (get_next_join_cache(&num,&thread)) {
        //printf("pthread_join start %i\n",num);
        pthread_join(thread,NULL);
        //printf("pthread_join ends %i\n",num);
    }
}


int wait_get_thread_cache (void) {
int n;
/*
struct timeval t1,t2;

    gettimeofday(&t1,NULL);
*/
    do {
        n = acquire_thread_cache();
        if (n == -1) {
                usleep(1000*100);
        }
	/*
	gettimeofday(&t2,NULL);
	if ((t2.tv_sec-t1.tv_sec) > 5) {
		printf("\nbusy %i\n",get_threads_cache_busy());
		panic("dead lock!");
	}
	*/
	dispatch_joins_cache();
    }
    while (n == -1);
    return (n);
}

void wait_cache_threads_busy (void) {
    while (get_threads_cache_busy() > 0) {
        usleep(1000*100);
    }
    sleep(1);
}

struct cache_params {
    int head;
    int num_thread;
};

void fill_cache_head (int num_thread, int head) {
struct entries *e;

    e = get_entries_disk (head,num_thread);
    if (e == NULL) {
	   panic("fill_cache get_entries_disk.");
    }
    if (!add_cache_entries (head,e)) {
	   // No more memory
           //panic("fill_cache add_cache_entries.");
    }
}

void *get_entries_function (void *ptr) {
struct cache_params *p;

    p = (struct cache_params *) ptr;
    //printf("start cache head %05X %i\n",p->head,p->num_thread);
    fill_cache_head (p->num_thread,p->head);
    //printf("end cache head %05X %i\n",p->head,p->num_thread);
    free_thread_cache(p->num_thread);
    //printf("released %05X %i\n",p->head,p->num_thread);
    free(p);
}

void launch_get_entries (int num_thread,int head) {
//pthread_t thread;
struct cache_params *p;

    p = malloc(sizeof(struct cache_params));
    p->head = head;
    p->num_thread = num_thread;
    //printf("launch head: %i %05X\n",p->num_thread,p->head);
    pthread_create(&info_cache[num_thread].thread, NULL, get_entries_function, (void*) p);
    //printf("launched head: %i %05X\n",p->num_thread,p->head);
}

/*
long long fill_cache (void) {
int n = 0;
//char head[MIN_STR];
struct entries *e;
long long count = 0L;

    memory = 0;
    printf("Caching hashes ...\n");
    for (n=0;n<ENTRIES;n++) {
        if (memory >= max_memory) {
		printf("\nfill_cache: memory full\n");
		break;
	}
        //sprintf(head,"%05X",n);
	//printf("try head %s\n",head);
	//printf("Memory: %lliM\n",memory/(1024L*1024L));
	e = get_entries_disk(n);
	if (e == NULL) {
		panic("fill_cache get_entries_disk.");
	}
        if (!add_cache_entries (n,e)) {
		panic("fill_cache add_cache_entries.");
	}
	count += e->num;
	printf("Head: %05X Memory: %lliM Passwords: %lli\r",n,memory/(1024L*1024L),count);
	fflush(stdout);
	//printf("head %s in cache\n",head);
    }
    printf("\nDone.\n");
    return(count);
}
*/

long long fill_cache (void) {
int n = 0,t;
//char head[MIN_STR];
struct entries *e;
//long long count = 0L;
unsigned long long m;

    //memory = 0;
    set_memory_counter(0L,0L);
    printf("Caching hashes ...\n");
    for (n=0;n<ENTRIES;n++) {
	m = get_memory_counter();
        if (m >= max_memory) {
		printf("\nfill_cache: memory full\n");
                break;
        }
	//printf("busy: %i\n",get_threads_cache_busy());
	t = wait_get_thread_cache();
	launch_get_entries(t,n);
    }
    wait_cache_threads_busy();
    printf("\nDone.\n");
    return(count);
}


int hash_to_index (char *hash) {
int n;

    n = (((int)hash[0]) & 0xf0) << 12;
    n += (((int)hash[0]) & 0x0f) << 12;
    n += (((int)hash[1]) & 0xf0) << 4;
    n += (((int)hash[1]) & 0x0f) << 4;
    n += (((int)hash[2]) & 0xf0) >> 4;
    return (n);
}

static inline void hash_to_tail (char *hash,struct entry *e)  {
    *e = *((struct entry *) (&hash[2]));
    e->h[0] &= 0x0f;
}

int checkpass (char *pass) {
unsigned char hash[SHA1_LEN];
//char buffer[MAX_STR];
//char head[MIN_STR];
//char tail[MIN_STR];
struct entry tail;
//FILE *f;
long l,ll;
char *p;
struct entries *e;
int lcache;
int lret = FALSE;
int n_head;

    //printf("pass: %s\n",pass);
    sha1(pass,hash);
    //sha1_to_string (hash,buffer);
    //printf("%s\n",buffer);
    n_head = hash_to_index (hash);
    //printf("head: %05X\n",n_head);
    //strcpy(head,buffer);
    //head[5] = 0;
    //strcpy(tail,buffer+5);
    hash_to_tail (hash,&tail);
    //print_entry(&tail);
    lcache = FALSE;
    //n_head = head_to_index(head);
    e = get_entries_cache (n_head);
    if (e == NULL) {
    	e = get_entries_disk (n_head,0);
    }
    else {
	lcache = TRUE;
	//printf("Head %s cached.\n",head);
    }
    //print_entries(e);
    if (find_tail_entries(&tail,e)) {
	//strcpy (res,"<deprecated>");
	lret = TRUE;
    }
    if (!lcache) {
	add_cache_entries (n_head,e);
    }
    return (lret);
}

FILE *open_append(void) {
FILE *f;

    recovered = 0;
    d_recovered = 0;
    gettimeofday(&oldtime,NULL);
    if (!llog) return (NULL);
    remove(LOG);
    f = fopen(LOG, "a");
    if (f == NULL) {
        panic("appendpass error.");
    }
    return (f);
}

pthread_mutex_t mutex_append = PTHREAD_MUTEX_INITIALIZER;

void write_append(FILE *f,char *p,int deep) {
struct timeval newtime;
long long n,o;

    pthread_mutex_lock (&mutex_append);
    recovered++;
    if (deep) {
	d_recovered++;
    }
    if (llog) {
	gettimeofday(&newtime,NULL);
	o = (oldtime.tv_sec*1000L)+(oldtime.tv_usec)/1000L;
	n = (newtime.tv_sec*1000L)+(newtime.tv_usec)/1000L;
	if ((n-o) >= DISPLAY_MS) {
		oldtime = newtime;
		printf("Passwords recovered: %lli deep:%lli\r",recovered,d_recovered);
		fflush(stdout);
	}
    	fwrite (p,1,strlen(p),f);
    	fwrite ("\n",1,1,f);
    }
    else {
	printf("%s p:%lli d:%lli\n",p,recovered,d_recovered);
    }
    pthread_mutex_unlock (&mutex_append);
}

void close_append(FILE *f) {
    if (!llog) return;
    fclose(f);
}

void checkword (FILE *f,char *w,int deep,int predeep) {
int i;
char *a = ALPHA;
char *m = ALPHA_MIN;
char c[2];
char p[MAX_STR];
char res[MAX_STR];

    /*
    if (deep_min && deep && (strlen(w)>=FORCE_DEEP)) {
	a = ALPHA_MIN;
    }
    */
    //printf("a = '%s'\n",a);
    c[1] = 0;
    for (i=0;i<strlen(a);i++) {
	c[0] =a[i];
	strcpy (p,w);
	strcat (p,c);
	if (checkpass(p)) {
		//printf("%s\n",p);
		//appendpass(p);
		write_append(f,p,predeep);
		checkword(f,p,0,predeep);
	}
	else if (((deep < max_deep) && (!deep_min || (strchr(m,*c)!=NULL)))|| (strlen(p)<FORCE_DEEP)) {
		//printf("'%s' deep char: %s\n",w,c);
		checkword(f,p,deep+1,predeep|(strlen(p)>=FORCE_DEEP));
	}
    }
}

// ------------------------------------------------------------------

pthread_mutex_t mutex_nthreads = PTHREAD_MUTEX_INITIALIZER;
int nthreads = 0;

int get_threads(void) {
int n;

    pthread_mutex_lock (&mutex_nthreads);
    n = nthreads;
    pthread_mutex_unlock (&mutex_nthreads);
    return (n);
}

void inc_threads(void) {
    pthread_mutex_lock (&mutex_nthreads);
    nthreads++;
    pthread_mutex_unlock (&mutex_nthreads);
}

void dec_threads(void) {
    pthread_mutex_lock (&mutex_nthreads);
    nthreads--;
    pthread_mutex_unlock (&mutex_nthreads);
}

struct cw_params {
    FILE *f;
    char w[MAX_STR];
    int deep;
    int predeep;
};

void *checkword_function (void *ptr) {
struct cw_params *p;

    p = (struct cw_params *) ptr;
    checkword (p->f,p->w,p->deep,p->predeep);
    //printf("exit thread '%s' (%i-1)\n",p->w,get_threads());
    dec_threads();
    free(p);
}

void launch_checkword (FILE *f,char *w,int deep,int predeep) {
pthread_t thread;
struct cw_params *p;

    p = malloc(sizeof(struct cw_params));
    //printf("launch thread '%s' (%i+1)\n",w,get_threads());
    p->f = f;
    strcpy (p->w,w);
    p->deep = deep;
    p->predeep = predeep;
    inc_threads();
    pthread_create( &thread, NULL, checkword_function, (void*) p);
}

void wait_threads (void) {
    while (get_threads() >= max_threads) {
	usleep(1000*100);
    }
}

void end_threads (void) {
    //printf("wait ending threads ...\n");
    while (get_threads() > 0) {
	//printf("remaining threads: %i\n",get_threads());
        sleep(1);
    }
}


void checkword_mt (FILE *f,char *w) {
int i;
char a[] = ALPHA;
char c[2];
char p[MAX_STR];
char res[MAX_STR];

    nthreads = 0;
    c[1] = 0;
    for (i=0;i<strlen(a);i++) {
        c[0] =a[i];
	//printf("checkword_mt c='%s'\n",c);
        strcpy (p,w);
        strcat (p,c);
        if (checkpass(p)) {
                //printf("checkword_mt launch '%s'\n",p);
                write_append(f,p,0);
		wait_threads();
                launch_checkword(f,p,0,FALSE);
        }
        else if (strlen(p)<FORCE_DEEP) {
		wait_threads();
                launch_checkword(f,p,1,FALSE);
        }
    }
    end_threads();
    printf("\nexit.\n");
}

// --------------------------------------------
#define HELP "\
--------------------------------------------------------------\n\
Guessc ("MY_VERSION") programed by Alex Bassas.\n\
--------------------------------------------------------------\n\
usage: guessc [-c<num>][-n][-d<num>][-m][-t<num>] \"<root>\"\n\
\n\
\"<root>\"      => Root string to search, \"\" for all passwords\n\
-c<num>       => Cache size in Gb (default 8)\n\
-n            => Don't save the password to '"LOG"', print it\n\
-d<num>       => Max deep (default 0)\n\
-m            => Use min alphabet on deep>0\n\
-t<num>       => Num of threads (default 4)\n\
\n"

int main(int argc, char **argv) {
//char res[MAX_STR];
FILE *f;
long long c;
int p,i;
char root[MAX_STR];

    while ((p = getopt(argc, argv, "nd:c:mt:")) != -1) {
	switch (p) {
		case 'c':
			max_memory = atoi(optarg)*1024L*1024*1024L;
			break;
		case 'n':
			llog = FALSE;
			break;
		case 'd':
			max_deep = atoi(optarg);
			break;
		case 'm':
			deep_min = TRUE;
			break;
		case 't':
			max_threads = atoi(optarg);
			break;
		case '?':
		default:
			printf(HELP);
			exit(0);
	}
    }
    root[0] = 0;
    if (optind == argc) {
	printf(HELP);
	exit(0);
    }
    for (i=optind;i<argc;i++) {
	strcpy (root,argv[i]);
    }
    init_cache();
#ifdef PRECACHE
    c = fill_cache();
    printf("passwords in cache: %lli\n",c);
#endif
    f = open_append();
    checkword_mt(f,root);
    close_append(f);
    return (0);
}
