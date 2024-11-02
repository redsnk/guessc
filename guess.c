#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <unistd.h>
#include <pthread.h>
#ifdef USE_OPENSSL
#include <openssl/evp.h>
#endif

#define MY_VERSION	"v0.5"
#define TRUE		(1)
#define FALSE		(0)
#define MAX_STR		(1024)
#define MIN_STR		(64)
#define BASE 		"%s/src/pwnedpasswords/%s"
#define ALPHA		"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!\"·$%&/()='?¡¿<>,;.:-_+* |@#~[]^\\"
#define ALPHA_MIN	"abcdefghijklmnopqrstuvwxyz"
#define MAX_DEEP	0
#define SHA1_LEN	20
#define LOG		"guessc.txt"
#define MAX_MEMORY 	(1024L*1024L*1024L*14L)
#define FORCE_DEEP	4
#define MAX_THREADS	4
#define PRECACHE

long long max_memory = MAX_MEMORY;
int llog = TRUE;
int max_deep = MAX_DEEP;
int deep_min = FALSE;
int max_threads = MAX_THREADS;
long long recovered = 0;

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
	unsigned char h[16];
};

struct entries {
	short int num;
	struct entry e[1];
};

#define ENTRIES	0x100000

struct index {
	struct entries *i[ENTRIES];
};

struct index idx;
unsigned long long memory = 0;

void panic(char *txt) {
    printf("PANIC: %s\n",txt);
    exit(1);
}

void init_cache(void) {
int n;

    for (n=0;n<ENTRIES;n++) {
	idx.i[n] = NULL;
    }
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

unsigned char hex_to_num(char c) {
unsigned char n;

    if ((c>='0') && (c<='9')) {
	return (c-'0');
    }
    if ((c>='A') && (c<='F')) {
	return (c-'A'+10);
    }
    panic("hex_to_num error.");
}

unsigned char hex_to_byte(char *txt) {
unsigned char c;

    c = (hex_to_num(txt[0]) << 8) + hex_to_num(txt[1]);
    return (c);
}

int hex_to_bytes(char *txt,char *b) {
int i=0;
char *p;

    p = txt;
    while (*p) {
	b[i++] = hex_to_byte(p);
	p += 2;
    }
    return (i);
}

void tail_to_entry(char *txt,struct entry *e) {
char *p;
char buffer[MAX_STR];

    p = strchr(txt,':');
    if (p != NULL) {
	*p = 0;
    }
    strcpy(buffer,"0");
    strcat(buffer,txt);
    hex_to_bytes(buffer,e->h);
}

int cmp_entry (struct entry e1,struct entry e2) {
int n;

    for (n=0;n<16;n++) {
	if (e1.h[n] != e2.h[n]) {
		return (FALSE);
	}
    }
    return (TRUE);
}

int find_tail_entries (char *tail,struct entries *en) {
int n;
struct entry ei;

    tail_to_entry(tail,&ei);
    for (n=0;n<en->num;n++) {
	if (cmp_entry(ei,en->e[n])) {
		return (TRUE);
	}
    }
    return (FALSE);
}

struct entries *txt_to_entries(char *txt,int len) {
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
	t = p+2;
	en->e[en->num++] = ei;
    }
    en = realloc(en,sizeof(struct entries)+(sizeof(struct entry)*(en->num-1)));
    return (en);
}

int head_to_index(char *head) {
int n;

    n = (int)strtol(head, NULL, 16);
    //printf("head: '%s' = %i\n",head,n);
    return (n);
}

int add_cache_entries (char *head,struct entries *e) {
int n;

    if (memory < max_memory) {
    	n = head_to_index(head);
    	if (idx.i[n] == NULL) {
		idx.i[n] = e;
		memory += sizeof(struct entries)+(sizeof(struct entry)*(e->num-1));
        	return (TRUE);
    	}
    }
    free(e);
    return (FALSE);
}

struct entries *get_entries_cache (char *head) {
int n;

    n = head_to_index(head);
    return (idx.i[n]);
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

struct entries *get_entries_disk (char *head) {
struct entries *e;
char buffer[MAX_STR];
long l,ll;
char *p;
FILE *f;

    sprintf (buffer,BASE,getenv("HOME"),head);
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
	fclose(f);
        // add '0d0a00' at the end
        p[l] = '\r';
        p[l+1] = '\n';
        p[l+2] = 0;
        e = txt_to_entries(p,l);
        free(p);
        //printf("%li\n",l);
    }
    else {
	printf("name: %s\n",buffer);
	panic("get_entries_disk fopen.");
    }
    return (e);
}

long long fill_cache (void) {
int n = 0;
char head[MIN_STR];
struct entries *e;
long long count = 0L;

    memory = 0;
    printf("Caching hashes ...\n");
    for (n=0;n<ENTRIES;n++) {
        if (memory >= max_memory) {
		printf("fill_cache: memory full\n");
		break;
	}
        sprintf(head,"%05X",n);
	//printf("try head %s\n",head);
	//printf("Memory: %lliM\n",memory/(1024L*1024L));
	e = get_entries_disk(head);
	if (e == NULL) {
		panic("fill_cache get_entries_disk.");
	}
        if (!add_cache_entries (head,e)) {
		panic("fill_cache add_cache_entries.");
	}
	count += e->num;
	printf("Head: %s Memory: %lliM Passwords: %lli\r",head,memory/(1024L*1024L),count);
	fflush(stdout);
	//printf("head %s in cache\n",head);
    }
    printf("\nDone.\n");
    return(count);
}


int checkpass (char *pass,char *res) {
unsigned char hash[SHA1_LEN];
char buffer[MAX_STR];
char head[MIN_STR];
char tail[MIN_STR];
FILE *f;
long l,ll;
char *p;
struct entries *e;
int lcache;
int lret = FALSE;

    sha1(pass,hash);
    sha1_to_string (hash,buffer);
    //printf ("%s\n",buffer);
    strcpy(head,buffer);
    head[5] = 0;
    strcpy(tail,buffer+5);
    lcache = FALSE;
    e = get_entries_cache (head);
    if (e == NULL) {
    	e = get_entries_disk (head);
    }
    else {
	lcache = TRUE;
	//printf("Head %s cached.\n",head);
    }
    if (find_tail_entries(tail,e)) {
	strcpy (res,tail);
	lret = TRUE;
    }
    if (!lcache) {
	add_cache_entries (head,e);
    }
    return (lret);
}

FILE *open_append(void) {
FILE *f;

    recovered = 0;
    if (!llog) return (NULL);
    remove(LOG);
    f = fopen(LOG, "a");
    if (f == NULL) {
        panic("appendpass error.");
    }
    return (f);
}

pthread_mutex_t mutex_append = PTHREAD_MUTEX_INITIALIZER;

void write_append(FILE *f,char *p) {
    pthread_mutex_lock (&mutex_append);
    recovered++;
    if (llog) {
	printf("Passwords recovered: %lli\r",recovered);
	fflush(stdout);
    	fwrite (p,1,strlen(p),f);
    	fwrite ("\n",1,1,f);
    }
    else {
	printf("%s\n",p);
    }
    pthread_mutex_unlock (&mutex_append);
}

void close_append(FILE *f) {
    if (!llog) return;
    fclose(f);
}

void checkword (FILE *f,char *w,int deep) {
int i;
char *a = ALPHA;
char c[2];
char p[MAX_STR];
char res[MAX_STR];

    if (deep_min && deep && (strlen(w)>=FORCE_DEEP)) {
	a = ALPHA_MIN;
    }
    //printf("a = '%s'\n",a);
    c[1] = 0;
    for (i=0;i<strlen(a);i++) {
	c[0] =a[i];
	strcpy (p,w);
	strcat (p,c);
	if (checkpass(p,res)) {
		//printf("%s\n",p);
		//appendpass(p);
		write_append(f,p);
		checkword(f,p,0);
	}
	else if ((deep < max_deep) || (strlen(p)<FORCE_DEEP)) {
		checkword(f,p,deep+1);
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
};

void *checkword_function (void *ptr) {
struct cw_params *p;

    p = (struct cw_params *) ptr;
    checkword (p->f,p->w,p->deep);
    //printf("exit thread '%s' (%i-1)\n",p->w,get_threads());
    dec_threads();
    free(p);
}

void launch_checkword (FILE *f,char *w,int deep) {
pthread_t thread;
struct cw_params *p;

    p = malloc(sizeof(struct cw_params));
    //printf("launch thread '%s' (%i+1)\n",w,get_threads());
    p->f = f;
    strcpy (p->w,w);
    p->deep = deep;
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


void checkword_mt (FILE *f,char *w,int deep) {
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
        if (checkpass(p,res)) {
                //printf("checkword_mt launch '%s'\n",p);
                write_append(f,p);
		wait_threads();
                launch_checkword(f,p,0);
        }
        else if ((deep < max_deep) || (strlen(p)<FORCE_DEEP)) {
		wait_threads();
                launch_checkword(f,p,deep+1);
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
-c<num>       => Cache size in Gb (default 14)\n\
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
    checkword_mt(f,root,0);
    close_append(f);
    return (0);
}
