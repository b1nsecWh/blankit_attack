/*
  base:https://github.com/rudyjantz/blankit/blob/main/replace_probed/decrypt_probe.cpp.for-docker
  simplified, removed comments and beautified
*/
#include "pin.H"
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/time.h>
#include <deque>
#include <set>
#include "blankit.h"

using namespace std;



char BLANKIT_APP_NAME[256];
char BLANKIT_APPROVED_LIST[256]; // glibc
char BLANKIT_PREDICT_SETS[256];


#define MAGIC_OFFSET 14


#define REL_STATIC_REACH_FUNCS_FILE "blankit_attack/data/staticReachableFuncs"
#define RWX_PERM (PROT_READ | PROT_WRITE | PROT_EXEC)
#define RX_PERM  (PROT_READ | PROT_EXEC)

FILE *blankit_log;

#define PRINTF_FLUSH(...)  do{ \
        fprintf(blankit_log, __VA_ARGS__); \
        fflush(blankit_log); \
    }while(0)


typedef enum{
    E_BLANK_STATE_INACTIVE     = 0,
    E_BLANK_STATE_ACTIVE       = 1,
    E_BLANK_STATE_MISPREDICTED = 2,
    E_BLANK_STATE_DONE         = 3,
}blank_state_e;

typedef struct{
    int num_no_predicts;
    int num_mispredicts;
    int num_underpredicts;
    int num_overpredicts;
    int num_correct_predicts;
    int num_correct_full_chain_predicts;

    unsigned long num_blankit_predict_probes;
    unsigned long num_copy_probes;
}blankit_stats_t;

blankit_stats_t blankit_stats = {0};

int BLANKIT_TRACE_COUNT_FREQ = 1000;


int page_size;
blank_state_e blank_state = E_BLANK_STATE_INACTIVE;
map<char *, unsigned int> copied_funcs;


vector<string>       instr_funcs_libc;
vector<string>       instr_funcs_libm;
vector<string>       instr_funcs_libgcc;
vector<string>       instr_funcs_libstdcpp;
vector<string>       instr_funcs_libdl;
vector<string>       instr_funcs_libpthread;
vector<string>       instr_funcs_libcrypt;
vector<string>       instr_funcs_libpcre;
vector<string>       instr_funcs_libz;
vector<string>       instr_funcs_libcrypto;
vector<string>       instr_funcs_libutil;
vector<string>       instr_funcs_libresolv;
vector<string>       instr_funcs_libssh;
vector<string>       instr_funcs_libnss_compat;
vector<string>       instr_funcs_libnsl;
vector<string>       instr_funcs_libnss_nis;
vector<string>       instr_funcs_libnss_files;
vector<set<string> > pred_sets;
int pred_set_idx;
int old_pred_set_idx;
map<char *, string> addr_to_name;
map<char *, unsigned int> addr_to_size;
map<char *, void *> addr_to_copy;
map<string, pair<char *, int> > name_to_addr_and_size;
map<string, set<string> > statically_reachable_funcs;

string *entry_lib_func_p;

static inline
void remap_permissions(char *addr, int size, int perm)
{
    char *aligned_addr_base;
    char *aligned_addr_end;
    int size_to_remap;

    // PRINTF_FLUSH("remap_permissions():\n");

    aligned_addr_base = (char *) ((unsigned long)(addr) & ~(page_size - 1));
    aligned_addr_end  = (char *) ((unsigned long)(addr+size) & ~(page_size - 1));
    size_to_remap = page_size + (aligned_addr_end - aligned_addr_base);
    // PRINTF_FLUSH("  aligned_addr_base: %p\n", aligned_addr_base);
    // PRINTF_FLUSH("  aligned_addr_end:  %p\n", aligned_addr_end);
    // PRINTF_FLUSH("  size_to_remap:     %d\n", size_to_remap);

    if(mprotect(aligned_addr_base, size_to_remap, perm) == -1){
        PRINTF_FLUSH("mprotect error\n");
    }
    // PRINTF_FLUSH("  mprotect succeeded\n");
}

static inline
void blank_func(char *addr_base, int size_cp)
{
    // PRINTF_FLUSH("blank_func()\n");
    memset(addr_base + MAGIC_OFFSET, 0, size_cp);
    // PRINTF_FLUSH("  memset succeeded\n");
}
static inline
void copy_func(void *copy_of_func, char *addr_base, int size_cp)
{
    // PRINTF_FLUSH("copy_func():\n");
    memcpy(copy_of_func, addr_base + MAGIC_OFFSET, size_cp);
    // PRINTF_FLUSH("  memcpy succeeded\n");
}

static inline
void probe_copy_aux(void *copy_of_func, char *addr_base, unsigned int size_cp)
{
    // PRINTF_FLUSH("  copy_of_func: %p\n", copy_of_func);
    // PRINTF_FLUSH("  addr_base:    %p\n", addr_base);
    // PRINTF_FLUSH("  size_cp:      %d\n", size_cp);
    // PRINTF_FLUSH("  name:         %s\n", addr_to_name[addr_base].c_str());


    remap_permissions(addr_base, size_cp, RWX_PERM);

    memcpy(addr_base + MAGIC_OFFSET, copy_of_func, size_cp);

    copied_funcs[addr_base] = size_cp;

    remap_permissions(addr_base, size_cp, RX_PERM);
}



void probe_copy(void *copy_of_func, char *addr_base, unsigned int size_cp)
{


    PRINTF_FLUSH("probe_copy() ");
    if(copied_funcs.find(addr_base) != copied_funcs.end()){
        PRINTF_FLUSH("\t%s in copied_funcs\n",addr_to_name[addr_base].c_str());
        return;
    }

    PRINTF_FLUSH("\tchecking Function: %s\t predict ID:%d: ", addr_to_name[addr_base].c_str(),pred_set_idx);

    if(pred_sets[pred_set_idx].find(addr_to_name[addr_base])
       != pred_sets[pred_set_idx].end()){
        PRINTF_FLUSH("\n===========\n");   

        for(set<string>::iterator it = pred_sets[pred_set_idx].begin();
            it != pred_sets[pred_set_idx].end();
            it++){

            if(name_to_addr_and_size.count((*it).c_str()) > 0){
                pair<char *, int> addr_and_size = name_to_addr_and_size[*it];
                PRINTF_FLUSH(" copy back: %25s\t %p => %p size:%d\n",
                             (*it).c_str(),
                             addr_to_copy[addr_and_size.first],
                             addr_and_size.first,
                             addr_and_size.second);
                // PRINTF_FLUSH("addr_and_size.second: %u\n", addr_and_size.second);
                probe_copy_aux(addr_to_copy[addr_and_size.first],
                               addr_and_size.first,
                               addr_and_size.second);
            }
        }
        PRINTF_FLUSH("===========\n");   

    }else{
        PRINTF_FLUSH("\t mispredict or attack\n");
    }
    
    probe_copy_aux(copy_of_func, addr_base, size_cp);
}


static inline
void probe_blank_aux(void)
{
    // PRINTF_FLUSH("probe_blank_aux()\n");
    for(map<char *, unsigned int>::iterator it = copied_funcs.begin();
        it != copied_funcs.end();
        ++it){
        char *addr = it->first;
        unsigned int size = it->second;

        // PRINTF_FLUSH("  blanking %p %d %s\n", addr, size, addr_to_name[addr].c_str());
        remap_permissions(addr, size, RWX_PERM);
        blank_func(addr, size);
        remap_permissions(addr, size, RX_PERM);
    }
    copied_funcs.clear();
    // PRINTF_FLUSH("  succeeded\n");
}


void probe_blankit_predict(int predict_idx)
{

    PRINTF_FLUSH("probe_blankit_predict()");
    PRINTF_FLUSH("\tidx: %d\n", predict_idx);

    probe_blank_aux();

    pred_set_idx = predict_idx;
}


BOOL FindAndCheckRtn(IMG img, string rtnName, RTN& rtn)
{
    rtn = RTN_FindByName(img, rtnName.c_str());

    if(RTN_Valid(rtn)){
        if(!RTN_IsSafeForProbedInsertion(rtn)){
            return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}



template<typename Out>
void split(const string &s, char delim, Out result)
{
    stringstream ss(s);
    string item;
    while(getline(ss, item, delim)){
        *(result++) = item;
    }
}

vector<string> split(const string &s, char delim)
{
    vector<string> elems;
    split(s, delim, back_inserter(elems));
    return elems;
}

void init_pred_sets(void)
{
    long file_size;
    size_t nmemb_read;

    FILE *fp = fopen(BLANKIT_PREDICT_SETS, "r");
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);  // rewind

    char *file_data = (char *) malloc(file_size);
    nmemb_read = fread(file_data, file_size, 1, fp);
    assert(nmemb_read == 1);

    set<string> empty;
    istringstream iss(file_data);
    vector<string> parts;
    for(string line; getline(iss, line); ){
            set<string> preds;
            parts = split(line, ';');
            if(parts.size() == 0){
                pred_sets.push_back(preds); // index 0 is ignored
                continue;
            }

            for(vector<string>::iterator it = parts.begin(); it != parts.end(); it++){
                if(*it == ""){
                    continue;
                }
                preds.insert(*it);
            }
            preds.erase(parts.back());
            pred_sets.push_back(preds);
    }

    PRINTF_FLUSH("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~blankit: predict sets~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    int idx = 0;
    for(vector<set<string> >::iterator it = pred_sets.begin(); it != pred_sets.end(); it++){
        PRINTF_FLUSH("idx: %d\n", idx);
        for(set<string>::iterator itt = (*it).begin(); itt != (*it).end(); itt++){
            PRINTF_FLUSH("  %s", itt->c_str());
        }
        PRINTF_FLUSH("\n");
        idx++;
    }
    PRINTF_FLUSH("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

    free(file_data);
    fclose(fp);
}



void init_instr_funcs(char *filename, vector<string> &instr_funcs)
{
    long file_size;
    size_t nmemb_read;

    FILE *fp = fopen(filename, "r");
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);  // rewind

    char *file_data = (char *) malloc(file_size);
    nmemb_read = fread(file_data, file_size, 1, fp);
    assert(nmemb_read == 1);

    istringstream iss(file_data);
    vector<string> parts;
    for(string line; getline(iss, line); ){
            instr_funcs.push_back(line);
    }

    free(file_data);
    fclose(fp);
    
}

void init_statically_reachable_funcs(void)
{
    long file_size;
    size_t nmemb_read;

    #define STATIC_REACH_FUNCS_FILE_SZ 256
    char static_reach_funcs_file[STATIC_REACH_FUNCS_FILE_SZ];
    int rv;
    

    rv = snprintf(static_reach_funcs_file,
                  STATIC_REACH_FUNCS_FILE_SZ,
                  "%s/%s",
                  getenv("HOME"),
                  REL_STATIC_REACH_FUNCS_FILE);
    if(rv >= STATIC_REACH_FUNCS_FILE_SZ){
        printf("ERROR: path to static reachability functions file is too" \
                     "many characters (%d >= %d)\n", rv, STATIC_REACH_FUNCS_FILE_SZ);
        exit(1);
    }

    FILE *fp = fopen(static_reach_funcs_file, "r");
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);  // rewind

    char *file_data = (char *) malloc(file_size);
    nmemb_read = fread(file_data, file_size, 1, fp);
    assert(nmemb_read == 1);

    istringstream iss(file_data);
    vector<string> parts;
    for(string line; getline(iss, line); ){
            //cout << line << endl;
            parts = split(line, ':');
            for(vector<string>::iterator it = parts.begin(); it != parts.end(); it++){
                //cout << *it << endl;
            }
            string func_name = parts[0];
            //int num_statically_reachable_funcs = parts[1];
            parts = split(parts[2], ',');
            for(vector<string>::iterator it = parts.begin(); it != parts.end(); it++){
                //cout << *it << endl;
                statically_reachable_funcs[func_name].insert(*it);
            }
    }

    free(file_data);
    fclose(fp);
}


void image_load(IMG &img,
                char *approved_list,
                vector<string> &instr_funcs)
{
    RTN rtn;
    void *copy_of_func;
    char *addr_base;
    int size_cp = 0;
    unsigned int i = 0;

    PRINTF_FLUSH("\timage_load()\n");

    init_instr_funcs(approved_list, instr_funcs);

    for(i = 0; i < instr_funcs.size(); i++){
        PRINTF_FLUSH("\t\tRTN name: %25s", instr_funcs[i].c_str());

        if(!FindAndCheckRtn(img, instr_funcs[i], rtn)){
            PRINTF_FLUSH("  not adding probe. failed checks.\n");
            continue;
        }

        size_cp = RTN_Size(rtn) - MAGIC_OFFSET;
        if(size_cp < 1){
            PRINTF_FLUSH("  not adding probe. copy size is too small\n");
            continue;
        }

        addr_base    = (char *) RTN_Address(rtn);
        copy_of_func = malloc(size_cp);

        addr_to_name[addr_base] = RTN_Name(rtn);
        addr_to_size[addr_base] = size_cp;
        addr_to_copy[addr_base] = copy_of_func;
        name_to_addr_and_size[RTN_Name(rtn)] = make_pair(addr_base, size_cp);

        copy_func(copy_of_func, addr_base, size_cp);
        remap_permissions(addr_base, RTN_Size(rtn), RWX_PERM);
        blank_func(addr_base, size_cp);
        remap_permissions(addr_base, RTN_Size(rtn), RX_PERM);

        RTN_InsertCallProbed(rtn, IPOINT_BEFORE, AFUNPTR( probe_copy ),
                             IARG_PTR, copy_of_func,
                             IARG_PTR, addr_base,
                             // safe cast. see a few lines up where we ignore
                             // continue to the next iteration if size < 1
                             IARG_UINT32, (unsigned int) size_cp,
                             IARG_END);
        PRINTF_FLUSH("\tblanked √\n");
    }
    PRINTF_FLUSH("\tdone image_load()\n\n");
}

void image_load_libblankit(IMG &img)
{
    RTN rtn;

    PRINTF_FLUSH("image_load_libblankit()\n");

    rtn = RTN_FindByName(img, "blankit_predict");
    if(RTN_Valid(rtn) && RTN_IsSafeForProbedReplacement(rtn)){
        RTN_ReplaceProbed(rtn, AFUNPTR(probe_blankit_predict));
    }else{
        PRINTF_FLUSH("ERROR: blankit_predict failed checks\n");
        exit(1);
    }
}




KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
                            "o", "decrypt_probe.outfile", "specify file name");

INT32 Usage(void)
{
    cerr <<
        "This pin tool tests probe replacement.\n"
        "\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}


VOID ImageLoad(IMG img, VOID *v)
{

    PRINTF_FLUSH("Image name is: %s\n", IMG_Name(img).c_str());


    if(IMG_Name(img).find("libc.so") != string::npos){
        image_load(img, BLANKIT_APPROVED_LIST, instr_funcs_libc);
    }else if(IMG_Name(img).find("libblankit.so") != string::npos){
        image_load_libblankit(img);
    }

}


int main(int argc, CHAR *argv[])
{

    PIN_InitSymbols();

    if(const char *app_name = getenv("BLANKIT_APP_NAME")){
        printf("BLANKIT_APP_NAME: %s\n", app_name);
        strcpy(BLANKIT_APP_NAME, app_name);
    }else{
        printf("\nERROR: Must supply BLANKIT_APP_NAME env variable\n");
        exit(1);
    }
    
    if(const char *approved_list = getenv("BLANKIT_APPROVED_LIST")){
        printf("BLANKIT_APPROVED_LIST: %s\n", approved_list);
        strcpy(BLANKIT_APPROVED_LIST, approved_list);
    }else{
        printf("\nERROR: Must supply BLANKIT_APPROVED_LIST env variable\n");
        exit(1);
    }

    if(const char *blankit_predict_sets = getenv("BLANKIT_PREDICT_SETS")){
        printf("BLANKIT_PREDICT_SETS: %s\n", blankit_predict_sets);
        strcpy(BLANKIT_PREDICT_SETS, blankit_predict_sets);
    }else{
        printf("\nERROR: Must supply BLANKIT_PREDICT_SETS env variable\n");
        exit(1);
    }

    blankit_log = fopen("blankit.log", "w");

    init_statically_reachable_funcs();
    init_pred_sets();


    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }


    IMG_AddInstrumentFunction(ImageLoad, 0);

    page_size = sysconf(_SC_PAGE_SIZE);
    if(page_size == -1){
        PRINTF_FLUSH("ERROR: Unable to get system page size\n");
        return 1;
    }

    PIN_StartProgramProbed();

    return 0;
}
