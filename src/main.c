// https://github.com/cocoahuke/universalmigparser
// Copyright (c) 2018 com.cocoahuke. All rights reserved.

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <regex.h>

//bool variable as switch for control program
const char *TARGET_FILE_PATH = "../xnu-2782.40.9_2/BUILD/obj/RELEASE_X86_64/osfmk/RELEASE/device/device_user.c";
bool PRINT_REQUEST_AND_REPLY_BOTH = true;
bool PRINT_REQEUST_ONLY_OTW_REPLY_ONLY = false;
bool ENABLE_FUNCTION_NAME_FILTER = false;
//End

typedef enum{
    return_failed = -1,
    return_success
} tmp_return_t;

typedef struct arr_entry{
    void *key;
    void *value;
    struct arr_entry *next;
}arr_entry_t;

typedef struct arr{
    arr_entry_t *entry_list;
    uint32_t count;
}arr_t;

#define ARRAY_MAX 128

typedef struct{
    void *data;
    size_t len;
}heap_t;

heap_t *heap_new(){
    heap_t *new = malloc(sizeof(heap_t));
    if(!new) return NULL;
    bzero(new, sizeof(heap_t));
    return new;
}

void heap_free(heap_t *heap){
    if(heap){
        if(heap->data){
            free(heap->data);
        }
        heap->data = NULL;
        heap->len = 0;
        *(intptr_t*)heap = (intptr_t)0xdeedbeef;
        free(heap);
    }
}

heap_t *heap_renewSize(heap_t *heap, size_t new_len){
    if(!heap)
        return NULL;
    if(!heap->data)
        return NULL;
    if(new_len <= heap->len)
        return NULL;
    
    char *tmp_ptr = realloc(heap->data, new_len);
    if(!tmp_ptr)
        return NULL;
    bzero(tmp_ptr + heap->len, new_len - heap->len);
    heap->data = tmp_ptr;
    heap->len = new_len;
    
    return heap;
}

heap_t *string_format_core(const char *fmt, va_list args){
    if(!fmt)
        return NULL;
    
    char *str = NULL;
    vasprintf(&str, (const char*)fmt, args);
    if(!str)
        return NULL;
    
    heap_t *rt_data = heap_new();
    rt_data->data = str;
    rt_data->len = strlen(str);
    return rt_data;
}

heap_t *string_format(const char *fmt,...){
    heap_t *rt_data = NULL;
    
    va_list args;
    va_start (args, fmt);
    rt_data = string_format_core(fmt, args);
    va_end (args);
    
    return rt_data;
}

heap_t *string_appending_format(heap_t *orig_heap, const char *fmt, ...){
    if(!orig_heap)
        return NULL;
    
    heap_t *append_str = NULL;
    
    va_list args;
    va_start (args, fmt);
    append_str = string_format_core(fmt, args);
    va_end (args);
    
    if(!append_str)
        return NULL;
    
    uint32_t old_len = (uint32_t)orig_heap->len;
    orig_heap = heap_renewSize(orig_heap, orig_heap->len + append_str->len + 1);
    if(!orig_heap){
        heap_free(append_str);
        return NULL;
    }
    
    memcpy(orig_heap->data + old_len, append_str->data, append_str->len);
    orig_heap->len --;
    ((char*)orig_heap->data)[orig_heap->len] = '\0';
    
    heap_free(append_str);
    return orig_heap;
}

arr_entry_t *arr_entry_alloc(){
    return malloc(sizeof(arr_entry_t));
}

void arr_entry_free(arr_entry_t *arr_entry){
    free(arr_entry);
}

arr_t *arr_alloc(){
    
    arr_t *new_arr = malloc(sizeof(arr_t));
    if(!new_arr)
        return NULL;
    
    bzero(new_arr, sizeof(arr_t));
    
    return new_arr;
}

void arr_free(arr_t *arr){
    if(!arr)
        return;
    
    arr_entry_t *entry_it = arr->entry_list;
    for(uint32_t i=0; entry_it && i<ARRAY_MAX; i++){
        arr_entry_t *tmp = entry_it->next;
        free(entry_it);
        entry_it = tmp;
    }
    
    free(arr);
}

arr_entry_t *arr_getByIndex(arr_t *arr, uint32_t index){
    if(!arr)
        return NULL;
    
    arr_entry_t *entry_it = arr->entry_list;
    for(uint32_t i=0; entry_it && i<ARRAY_MAX; i++){
        if(i == index)
            return entry_it;
        entry_it = entry_it->next;
    }
    return NULL;
}

tmp_return_t arr_add(arr_t *arr, void *key, void *value){
    
    if(!arr)
        return return_failed;
    
    arr_entry_t *new_entry = arr_entry_alloc();
    if(!new_entry)
        return return_failed;
    
    bzero(new_entry, sizeof(arr_entry_t));
    new_entry->key = key;
    new_entry->value = value;
    
    arr_entry_t *entry_it = arr->entry_list;
    if(!entry_it){
        arr->entry_list = new_entry;
        arr->count ++;
        return return_success;
    }
    
    for(uint32_t i=0; entry_it && i<ARRAY_MAX; i++){
        if(entry_it->key == key)
            break;
        if(!entry_it->next){
            entry_it->next = new_entry;
            arr->count ++;
            return return_success;
        }
        entry_it = entry_it->next;
    }
    
    arr_entry_free(new_entry);
    return return_failed;
}

size_t file_get_size(const char *path){
    struct stat buf;
    
    if ( stat(path,&buf) < 0 )
    {
        return 0;
    }
    return buf.st_size;
}

heap_t *file_read(const char *file_path){
    void *buf = NULL;
    
    size_t file_size = file_get_size(file_path);
    if(!file_size)
        return NULL;
    
    buf = malloc(file_size + 1);
    if(!buf)
        return  NULL;
    
    FILE *fp = fopen(file_path, "r");
    if(!fp){
        free(buf);
        return NULL;
    }
    
    if(fread(buf, 1, file_size, fp)!=file_size){
        free(buf);
        return NULL;
    }
    
    fclose(fp);
    
    if(buf){
        heap_t *rt_data = heap_new();
        rt_data->data = buf;
        rt_data->len = file_size;
        ((char*)rt_data->data)[rt_data->len] = '\0';
        return rt_data;
    }
    
    return NULL;;
}

void *memrmem(const void *membuf, const void *membuf_begin, const void *searchbuf, size_t searchbuf_len){
    size_t range_len = (size_t)membuf - (size_t)membuf_begin;
    if(range_len < searchbuf_len)
        return NULL;
    
    membuf -= searchbuf_len;
    for(; membuf >= membuf_begin;){
        if(!memcmp(membuf, searchbuf, searchbuf_len))
            return (void*)membuf;
        membuf --;
    }
    
    return NULL;
}

arr_t *regex_normal(char *source_text, const char *regex_pattern_fmt, ...){
    
    heap_t *regex_pattern = NULL;
    
    va_list args;
    va_start (args, regex_pattern_fmt);
    regex_pattern = string_format_core(regex_pattern_fmt, args);
    va_end (args);
    
    if(!regex_pattern)
        return NULL;
    
    arr_t *return_data = NULL;
    regex_t reg;
    int eflags = 0;
    size_t offset = 0;
    size_t length = strlen(source_text);
    size_t maxGroups = 1;
    regmatch_t all_matches[maxGroups];
    
    if(regcomp(&reg, regex_pattern->data, REG_EXTENDED| REG_ENHANCED| REG_UNGREEDY| REG_NEWLINE))
        goto End;
    
    while (regexec(&reg, source_text + offset, maxGroups, all_matches, eflags) == 0) {
        eflags = REG_NOTBOL;
        
        for (int g = 0; g < maxGroups; g++)
        {
            if (all_matches[g].rm_so == (size_t)-1)
                break;
            
            uint64_t match_len = (offset + all_matches[g].rm_eo) - (offset + all_matches[g].rm_so);
            
            if(!return_data)
                return_data = arr_alloc();
            
            arr_add(return_data, source_text + (offset + all_matches[g].rm_so), (void*)match_len);
        }
        
        offset += all_matches[0].rm_eo;
        
        if (all_matches[0].rm_so == all_matches[0].rm_eo) {
            offset += 1;
        }
        
        if (offset > length) {
            break;
        }
    }
    
End:
    regfree(&reg);
    if(regex_pattern)
        heap_free(regex_pattern);
    return return_data;
}

tmp_return_t regex_grouping(char *source_text, const char *regex_pattern, int group_count, ...){
    
    tmp_return_t xr = 1;
    arr_t **return_data_groups[group_count];
    regex_t reg;
    int eflags = 0;
    size_t offset = 0;
    size_t length = strlen(source_text);
    size_t maxGroups = group_count;
    regmatch_t all_matches[group_count];
    
    va_list args;
    va_start (args, group_count);
    for(int i = 0; i< group_count;i ++){
        return_data_groups[i] = va_arg(args, arr_t**);
    }
    va_end (args);
    
    if(regcomp(&reg, regex_pattern, REG_EXTENDED| REG_ENHANCED| REG_UNGREEDY| REG_NEWLINE)){
        xr = 1;
        goto End;
    }
    
    while (regexec(&reg, source_text + offset, maxGroups, all_matches, eflags) == 0) {
        eflags = REG_NOTBOL;
        
        for (int g = 0; g < maxGroups; g++)
        {
            arr_t **arr_group = return_data_groups[g];
            if(!arr_group)
                continue;
            
            if (all_matches[g].rm_so == (size_t)-1){
                xr = 1;
                break;
            }
            
            uint64_t match_len = (offset + all_matches[g].rm_eo) - (offset + all_matches[g].rm_so);
            
            if(!*arr_group){
                xr = 0;
                *arr_group = arr_alloc();
            }
            arr_add(*arr_group, source_text + (offset + all_matches[g].rm_so), (void*)match_len);
        }
        
        offset += all_matches[0].rm_eo;
        
        if (all_matches[0].rm_so == all_matches[0].rm_eo) {
            offset += 1;
        }
        
        if (offset > length) {
            break;
        }
    }
    
End:
    regfree(&reg);
    return xr;
}

#define CODEGEN_ADD(fmt...) do{ \
if(!hv_codegen) hv_codegen = string_format(fmt); \
else hv_codegen = string_appending_format(hv_codegen, fmt); \
}while(0)

#define printf_indent(indent_count, fmt...) do{\
printf("%*s", (indent_count)*4, ""); \
printf(fmt); \
}while(0)

int codegen_ipcstage = 1;
/*
 1: ipc_kmsg_copyin_header
 2: ipc_kmsg_copyin_body
 3: ipc_kmsg_copyout_header
 4: ipc_kmsg_copyout_body
 */

typedef struct Routine_Info{
    struct arr_entry full_name;
    struct arr_entry name;
    uint32_t msghid;
    struct arr_entry request_port;
    struct arr_entry reply_port;
    
    arr_t *arr_args; //Arg_Info array in Key
    arr_t *arr_request_stru_args; //Arg_Info array in Key
    arr_t *arr_reply_stru_args; //Arg_Info array in Key
}Routine_Info;

typedef struct Arg_Info{
    //shared members
    struct arr_entry full_name;
    struct arr_entry name;
    struct arr_entry type;
    
    //func args use only
    struct Arg_Info *link_struarg_request;
    struct Arg_Info *link_struarg_reply;
    bool isInRequest_port;
    bool isInReply_port;
    
    //request/reply members use only
    struct Arg_Info *link_funcparm; //Unused
    struct arr_entry deltasize_adjust;
    bool isInMsgh_body;
    uint32_t arrcount;
}Arg_Info;

/*
 This is the function print the value of variable according to the type of the variable. read my code for ref
 */
void codegen_printvar(heap_t *hv_codegen, Arg_Info *arginfo){
    
    bool isSendifTrueOtwRecv = false;
    if(codegen_ipcstage == 1 || codegen_ipcstage == 2)
        isSendifTrueOtwRecv = true;
    Arg_Info *struarg_info = isSendifTrueOtwRecv?arginfo->link_struarg_request:arginfo->link_struarg_reply;
    const char *tmpalias = isSendifTrueOtwRecv?"Request":"Reply";
    const char *inpoutp = isSendifTrueOtwRecv?"InP":"OutP";
    
#define TMPMACRO(X) (struarg_info&&struarg_info->type.key&&!memcmp(struarg_info->type.key, X, (uint32_t)struarg_info->type.value>(sizeof(X)-1)?(uint32_t)struarg_info->type.value:(sizeof(X)-1))||arginfo->type.key&&!memcmp(arginfo->type.key, X, (uint32_t)arginfo->type.value>(sizeof(X)-1)?(uint32_t)arginfo->type.value:(sizeof(X)-1)))
    
    if(arginfo->isInRequest_port || arginfo->isInReply_port || TMPMACRO("mach_msg_port_descriptor_t")){
        /*
         This if judgement is for "mach port object" aka "ipc port object" type variable, looks messy due to require different code in *_copyin and *_copyout
         */
        if(arginfo->isInRequest_port){
            if(isSendifTrueOtwRecv){
                CODEGEN_ADD("mach_port_t machport_%.*s = machport_remote;\n", arginfo->name.value, arginfo->name.key);
                CODEGEN_ADD("mach_port_name_t machport_%.*s_name = 0;\n", arginfo->name.value, arginfo->name.key);
                CODEGEN_ADD("if(machport_%.*s){\n", arginfo->name.value, arginfo->name.key);
            }
            else{
                CODEGEN_ADD("mach_port_t machport_%.*s = NULL;\n", arginfo->name.value, arginfo->name.key);
                CODEGEN_ADD("mach_port_name_t machport_%.*s_name = machport_remote;\n", arginfo->name.value, arginfo->name.key);
                CODEGEN_ADD("if(machport_%.*s_name){\n", arginfo->name.value, arginfo->name.key);
            }
        }
        
        if(TMPMACRO("mach_msg_port_descriptor_t")){
            if(isSendifTrueOtwRecv){
                CODEGEN_ADD("mach_port_t machport_%.*s = InP_%.*s->%.*s.name;\n", arginfo->name.value, arginfo->name.key, arginfo->name.value, arginfo->name.key, arginfo->name.value, arginfo->name.key);
                CODEGEN_ADD("mach_port_name_t machport_%.*s_name = 0;\n", arginfo->name.value, arginfo->name.key);
                CODEGEN_ADD("if(machport_%.*s){\n", arginfo->name.value, arginfo->name.key);
            }
            else{
                CODEGEN_ADD("mach_port_t machport_%.*s = NULL;\n", arginfo->name.value, arginfo->name.key);
                CODEGEN_ADD("mach_port_name_t machport_%.*s_name = (mach_port_name_t)OutP_%.*s->%.*s.name;\n", arginfo->name.value, arginfo->name.key, arginfo->name.value, arginfo->name.key, arginfo->name.value, arginfo->name.key);
                CODEGEN_ADD("if(machport_%.*s_name){\n", arginfo->name.value, arginfo->name.key);
            }
        }
        
        if(isSendifTrueOtwRecv){
            CODEGEN_ADD("if((vm_offset_t)machport_%.*s > VM_MIN_KERNEL_ADDRESS){\n", arginfo->name.value, arginfo->name.key);
            CODEGEN_ADD("ipc_entry_t ipcentry_%.*s = NULL;\n", arginfo->name.value, arginfo->name.key);
            CODEGEN_ADD("is_write_lock(space);\n");
            CODEGEN_ADD("ipc_hash_lookup(space, (ipc_object_t)machport_%.*s, &machport_%.*s_name, &ipcentry_%.*s);\n", arginfo->name.value, arginfo->name.key, arginfo->name.value, arginfo->name.key, arginfo->name.value, arginfo->name.key);
            CODEGEN_ADD("is_write_unlock(space);\n}\n\n");
        }
        else{
            CODEGEN_ADD("ipc_entry_t ipcentry_%.*s = ipc_entry_lookup(space, machport_%.*s_name);\n", arginfo->name.value, arginfo->name.key, arginfo->name.value, arginfo->name.key);
            CODEGEN_ADD("if(ipcentry_%.*s)\n", arginfo->name.value, arginfo->name.key);
            CODEGEN_ADD("machport_%.*s = (struct ipc_port*)(ipcentry_%.*s->ie_object);\n\n", arginfo->name.value, arginfo->name.key, arginfo->name.value, arginfo->name.key);
        }
        
        CODEGEN_ADD("printf_indent(indent_count+2, \"(IPC Port Name) 0x%%x\\n\", machport_%.*s_name);\n", arginfo->name.value, arginfo->name.key);
        CODEGEN_ADD("printf_indent(indent_count+2, \"(IPC Port Object) 0x%%llx\\n\", machport_%.*s);\n", arginfo->name.value, arginfo->name.key);
        //Maybe print object type name? (IKOT) %d\n, ip_kotype(machport_remote);
        
        CODEGEN_ADD("}else{\n");
        CODEGEN_ADD("printf_indent(indent_count+2, \"(NULL)\\n\");\n");
        CODEGEN_ADD("}\n");
    }
    else if(TMPMACRO("io_name_t")){
        
        CODEGEN_ADD("printf_indent(indent_count+2, \"(char*) %%s\\n\", %s_%.*s->%.*s);\n", inpoutp, arginfo->name.value, arginfo->name.key, arginfo->name.value, arginfo->name.key);
    }
    else if(TMPMACRO("uint32_t")){
        
        CODEGEN_ADD("printf_indent(indent_count+2, \"(uint32_t) 0x%%x\\n\", %s_%.*s->%.*s);\n", inpoutp, arginfo->name.value, arginfo->name.key, arginfo->name.value, arginfo->name.key);
    }
    else if(TMPMACRO("uint64_t")){
        
        CODEGEN_ADD("printf_indent(indent_count+2, \"(uint64_t) 0x%%llx\\n\", %s_%.*s->%.*s);\n", inpoutp, arginfo->name.value, arginfo->name.key, arginfo->name.value, arginfo->name.key);
    }
#pragma mark TODO: Add more support type
    /*
     Add more variable type here, or delete. do whatever you want. Read the code I wrote above for reference.
     */
    else{
        //When Type is not registered
        CODEGEN_ADD("printf_indent(indent_count+2, \"(Unregistered Type)\\n\");\n");
    }
}

//This is the global variable store collected info, codegen_laststep read this variable and print out the final code
arr_t *codegen_switchcases = NULL;

#pragma mark TODO: Build code inside every function
/*
 This function is building code for echo MIG function, add or remove code to suit your needs.
 
 Example:
 ....
 | mach_msg_id_t msgh_id = machmsg_head->msgh_id;
 | if(msgh_id >= ? && requesting_msgh_id <= ?){
 |   switch (msgh_id) {
 |     case ?:{
 |       //Each "case ????" corresponds a function
 |       //codegen_buildcode built code insert into here
 |     }
 |
 |   }
 */

void codegen_buildcode(Routine_Info *miginfo){
    if(!codegen_switchcases)
        codegen_switchcases = arr_alloc();
    
    bool isSendifTrueOtwRecv = false;
    if(codegen_ipcstage == 1 || codegen_ipcstage == 2)
        isSendifTrueOtwRecv = true;
    
    heap_t *hv_codegen = NULL;
    
    CODEGEN_ADD("printf_indent(indent_count, \"%.*s\\n\");\n\n", (int)miginfo->name.value, miginfo->name.key);
    
    arr_t *arr_tmpalias = isSendifTrueOtwRecv?miginfo->arr_request_stru_args:miginfo->arr_reply_stru_args;
    const char *tmpalias = isSendifTrueOtwRecv?"Request":"Reply";
    
    const char *retcode_str = "RetCode";
    bool isRetCodeInsideStru = false;
    
    CODEGEN_ADD("#pragma pack(4)\n");
    CODEGEN_ADD("typedef struct {\n");
    for(int i=0; i<arr_tmpalias->count; i++){
        arr_entry_t *ent = arr_getByIndex(arr_tmpalias, i);
        Arg_Info *struarg_info = ent->key;
        if(struarg_info){
            const char *excepts_str = "mach_msg_trailer_t";
            if(!memcmp(excepts_str, struarg_info->type.key, (uint32_t)strlen(excepts_str)>(uint32_t)struarg_info->type.value?(uint32_t)strlen(excepts_str):(uint32_t)struarg_info->type.value))
                continue;
            
            CODEGEN_ADD("%*s", 4, "");
            CODEGEN_ADD("%.*s\n", struarg_info->full_name.value, struarg_info->full_name.key);
            if(!memcmp(retcode_str, struarg_info->name.key, (uint32_t)strlen(retcode_str)>(uint32_t)struarg_info->name.value?(uint32_t)strlen(retcode_str):(uint32_t)struarg_info->name.value))
                isRetCodeInsideStru = true;
        }
    }
    CODEGEN_ADD("} %s __attribute__((unused));\n", tmpalias);
    CODEGEN_ADD("#pragma pack(0)\n");
    
    CODEGEN_ADD("__attribute__((unused)) %s *%s = (%s *)machmsg_head;\n", tmpalias, isSendifTrueOtwRecv?"InP":"OutP", tmpalias);
    
    CODEGEN_ADD("__attribute__((unused)) unsigned int msgh_size = machmsg_head->msgh_size;\n");
    CODEGEN_ADD("__attribute__((unused)) unsigned int msgh_size_delta;\n");
    
    if(!isSendifTrueOtwRecv){
        if(isRetCodeInsideStru){
            CODEGEN_ADD("if(OutP->RetCode != KERN_SUCCESS){\n");
            CODEGEN_ADD("printf_indent(indent_count+1, \"= RetCode: 0x%%x\\n\", OutP->RetCode);\n");
            CODEGEN_ADD("return;\n");
            CODEGEN_ADD("}\n");
        }
        else{
            CODEGEN_ADD("if((msgh_size != (mach_msg_size_t)sizeof(Reply)) && (msgh_size == (mach_msg_size_t)sizeof(mig_reply_error_t)) && (((mig_reply_error_t *)OutP)->RetCode != KERN_SUCCESS)){\n");
            CODEGEN_ADD("printf_indent(indent_count+1, \"= RetCode: 0x%%x\\n\", ((mig_reply_error_t *)OutP)->RetCode);\n");
            CODEGEN_ADD("return;\n");
            CODEGEN_ADD("}\n");
        }
    }
    CODEGEN_ADD("\n");
    
    //i=1: Skip mach_msg_header_t Head;
    for(int i=1; i<arr_tmpalias->count; i++){
        arr_entry_t *ent = arr_getByIndex(arr_tmpalias, i);
        Arg_Info *struarg_info = ent->key;
        if(struarg_info){
            
            //If same variable used in function arguments
            CODEGEN_ADD("__attribute__((unused)) %s *%s_%.*s = %s;\n", tmpalias, isSendifTrueOtwRecv?"InP":"OutP", struarg_info->name.value, struarg_info->name.key, isSendifTrueOtwRecv?"InP":"OutP");
            
            if(struarg_info->deltasize_adjust.key){
                if((i+1) == arr_tmpalias->count){
                    printf("ERROR\n");
                    exit(1);
                }
                arr_entry_t *ent_next = arr_getByIndex(arr_tmpalias, i+1);
                Arg_Info *struarg_info_next = ent_next->key;
                i++;
                
                CODEGEN_ADD("\n__attribute__((unused)) %s *%s_%.*s = %s;\n", tmpalias, isSendifTrueOtwRecv?"InP":"OutP", struarg_info_next->name.value, struarg_info_next->name.key, isSendifTrueOtwRecv?"InP":"OutP");
                
                CODEGEN_ADD("__attribute__((unused)) %.*s = %s->%.*s;\n", struarg_info->full_name.value-1, struarg_info->full_name.key, isSendifTrueOtwRecv?"InP":"OutP", struarg_info->name.value, struarg_info->name.key);
                
                CODEGEN_ADD("%.*s\n", struarg_info->deltasize_adjust.value, struarg_info->deltasize_adjust.key);
            }
        }
    }
    
    for(int i=0; i<miginfo->arr_args->count; i++){
        arr_entry_t *ent = arr_getByIndex(miginfo->arr_args, i);
        Arg_Info *arginfo = ent->key;
        if(arginfo){
            
            CODEGEN_ADD("\n//Argument %d: %.*s\n", i+1, arginfo->full_name.value, arginfo->full_name.key);
            if(arginfo->isInRequest_port){
                //If the argument is being passed from msgh_request_port
                
                if(isSendifTrueOtwRecv){
                    CODEGEN_ADD("printf_indent(indent_count+1, \"> %.*s =\\n\");\n", arginfo->full_name.value, arginfo->full_name.key);
                    codegen_printvar(hv_codegen, arginfo);
                }
                else{
                    CODEGEN_ADD("printf_indent(indent_count+1, \"X %.*s = (X)\\n\");\n", arginfo->full_name.value, arginfo->full_name.key);
                }
                
                continue;
            }
            
            if(!arginfo->link_struarg_request && !arginfo->link_struarg_reply){
                //Didn't found in request or reply structure
                CODEGEN_ADD("printf_indent(indent_count+1, \"? %.*s = (X)\\n\");\n\n", arginfo->full_name.value, arginfo->full_name.key);
                continue;
            }
            
            if(arginfo->link_struarg_request){
                
                if(isSendifTrueOtwRecv){
                    CODEGEN_ADD("printf_indent(indent_count+1, \"> %.*s =\\n\");\n", arginfo->full_name.value, arginfo->full_name.key);
                    codegen_printvar(hv_codegen, arginfo);
                    continue;
                }else if(!arginfo->link_struarg_reply){
                    CODEGEN_ADD("printf_indent(indent_count+1, \"X %.*s = (X)\\n\");\n", arginfo->full_name.value, arginfo->full_name.key);
                    continue;
                }
            }
            
            if(arginfo->link_struarg_reply){
                
                if(isSendifTrueOtwRecv){
                    CODEGEN_ADD("printf_indent(indent_count+1, \"X %.*s = (X)\\n\");\n", arginfo->full_name.value, arginfo->full_name.key);
                }
                else{
                    CODEGEN_ADD("printf_indent(indent_count+1, \"< %.*s =\\n\");\n", arginfo->full_name.value, arginfo->full_name.key);
                    codegen_printvar(hv_codegen, arginfo);
                }
                
                continue;
            }
            
        }
    }
    
    //End of code building
    if(((char*)hv_codegen->data)[hv_codegen->len-1] != '\n')
        CODEGEN_ADD("\n");
    arr_add(codegen_switchcases, (void*)(uint64_t)miginfo->msghid, hv_codegen);
}

bool onlyprint_once = true;

#pragma mark TODO: Build code outside of each function
/*
 It's the last function of this program, for build code outside of each function
 */
void codegen_laststep(){
    
    bool isSendifTrueOtwRecv = false;
    if(codegen_ipcstage == 1 || codegen_ipcstage == 2)
        isSendifTrueOtwRecv = true;
    
    uint32_t indent_count = 0;
    
    if(onlyprint_once){
        printf_indent(indent_count, "#include \"iokit_monitor.h\"\n\n");
        
        printf_indent(indent_count, "#undef printf\n");
        printf_indent(indent_count, "#define printf(args...) debug_print_toFile(args)\n");
        printf_indent(indent_count, "#define printf_indent(indent_count, fmt...) do{printf(\"%%*s\", (indent_count)*2, \"\"); printf(fmt); }while(0)\n\n");
        onlyprint_once = false;
    }
    
    if(isSendifTrueOtwRecv)
        printf_indent(indent_count, "void migtest_copyin(ipc_kmsg_t kmsg, ipc_space_t space){\n");
    else
        printf_indent(indent_count, "void migtest_copyout(ipc_kmsg_t kmsg, ipc_space_t space){\n");
    
    indent_count ++;
    printf_indent(indent_count, "int indent_count = 0;\n");
    
    printf_indent(indent_count, "#define _WALIGN_(x) (((x) + 3) & ~3)\n");
    printf_indent(indent_count, "__attribute__((unused)) mach_msg_header_t *machmsg_head = kmsg->ikm_header;\n");
    printf_indent(indent_count, "__attribute__((unused)) struct ipc_port *machport_local = machmsg_head->msgh_local_port;\n");
    printf_indent(indent_count, "__attribute__((unused)) struct ipc_port *machport_remote = machmsg_head->msgh_remote_port;\n");
    printf_indent(indent_count, "\n");
    printf_indent(indent_count, "printf_indent(indent_count, \"(%s)\");\n\n", isSendifTrueOtwRecv?"SEND":"RECV");
    
    if(isSendifTrueOtwRecv)
        printf_indent(indent_count, "mach_msg_id_t requesting_msgh_id = machmsg_head->msgh_id;\n");
    else
        printf_indent(indent_count, "mach_msg_id_t requesting_msgh_id = machmsg_head->msgh_id - 100;\n");
    
    uint32_t msgh_id_min=0, msgh_id_max=0;
    for(int i=0; i<codegen_switchcases->count; i++){
        arr_entry_t *each_switchcase = arr_getByIndex(codegen_switchcases, i);
        if(i == 0)
            msgh_id_min = msgh_id_max = (uint32_t)each_switchcase->key;
        else{
            uint32_t tmpnum = (uint32_t)each_switchcase->key;
            if(tmpnum < msgh_id_min)
                msgh_id_min = tmpnum;
            if(tmpnum > msgh_id_max)
                msgh_id_max = tmpnum;
        }
    }
    
    printf_indent(indent_count, "if(requesting_msgh_id >= %d && requesting_msgh_id <= %d){\n", msgh_id_min, msgh_id_max);
    printf_indent(indent_count+1, "switch (requesting_msgh_id) {\n");
    
    for(int i=0; i<codegen_switchcases->count; i++){
        arr_entry_t *each_switchcase = arr_getByIndex(codegen_switchcases, i);
        heap_t *aa = each_switchcase->value;
        uint32_t tmpnum = (uint32_t)each_switchcase->key;
        printf_indent(indent_count+2, "case %d:{\n", tmpnum);
        
        arr_t *bb = regex_normal(aa->data, ".*\\n");
        if(!bb)
            printf_indent(indent_count+3, "%s\n", aa->data);
        else{
            for(int i=0; i<bb->count; i++){
                arr_entry_t *cc = arr_getByIndex(bb, i);
                if(cc)
                    printf_indent(indent_count+3, "%.*s", (int)cc->value, cc->key);
            }
            arr_free(bb);
        }
        
        printf_indent(indent_count+2, "}break;\n");
    }
    
    printf_indent(indent_count+1, "}\n");
    printf_indent(indent_count, "}\n");
    printf_indent(indent_count, "printf_indent(indent_count, \"\\n\");\n");
    indent_count--;
    printf_indent(indent_count, "}\n");
}

void func_parse_request_routine(char *migroutine_start, char *migroutine_reply_start){
    
    char tmp_char;
    char *tmp_str, *tmp_str2;
    
    arr_t *arr_routine_args = NULL;
    arr_t *arr_request_args = NULL;
    arr_t *arr_reply_args = NULL;
    
    Routine_Info miginfo = {0};
    
    //Extract MIG Routine Info: Function name
    tmp_str = strstr(migroutine_start, " */");
    if(tmp_str){
        tmp_char = tmp_str[0];
        tmp_str[0] = '\0';
        
        miginfo.name.key = migroutine_start;
        miginfo.name.value = (void*)strlen(migroutine_start);
        tmp_str[0] = tmp_char;
    }
    
    //Extract MIG Routine Info: Function arguments
    tmp_str = strstr(migroutine_start, "(");
    if(!tmp_str){
        printf("Error\n");
        exit(1);
    }
    tmp_str2 = strstr(migroutine_start, ")");
    if(!tmp_str2){
        printf("Error\n");
        exit(1);
    }
    tmp_char = *tmp_str2;
    *tmp_str2 = '\0';
    regex_grouping(tmp_str, "[^()](.*)[,]?\n", 2, NULL, &arr_routine_args);
    *tmp_str2 = tmp_char;
    
    //Extract MIG Routine Info: Request Structure
    const char *stru_head_patt = "typedef struct {";
    const char *request_stru_patt = "} Request __attribute__((unused));";
    tmp_str = strstr(migroutine_start, request_stru_patt);
    if(tmp_str){
        tmp_str2 = memrmem(tmp_str, migroutine_start, stru_head_patt, strlen(stru_head_patt));
        if(tmp_str2){
            tmp_str2 += strlen(stru_head_patt);
            tmp_char = *tmp_str;
            *tmp_str = '\0';
            regex_grouping(tmp_str2, "\\s*?(.*)\\s*?\n", 2, NULL, &arr_request_args);
            *tmp_str = tmp_char;
        }
    }
    
    //Extract MIG Routine Info: Reply Structure
    const char *reply_stru_pattern = "} Reply __attribute__((unused));";
    tmp_str = strstr(migroutine_start, reply_stru_pattern);
    if(tmp_str){
        tmp_str2 = memrmem(tmp_str, migroutine_start, stru_head_patt, strlen(stru_head_patt));
        if(tmp_str2){
            tmp_str2 += strlen(stru_head_patt);
            tmp_char = *tmp_str;
            *tmp_str = '\0';
            regex_grouping(tmp_str2, "\\s*?(.*)\\s*?\n", 2, NULL, &arr_reply_args);
            *tmp_str = tmp_char;
        }
    }
    
    //Extract MIG Routine Info: Value of msgh_request_port
    const char *msgh_request_port_patt = "InP->Head.msgh_request_port = ";
    tmp_str = strstr(migroutine_start, msgh_request_port_patt);
    if(tmp_str){
        tmp_str += strlen(msgh_request_port_patt);
        tmp_str2 = strstr(tmp_str, ";");
        if(tmp_str2){
            tmp_char = *tmp_str2;
            *tmp_str2 = '\0';
            miginfo.request_port.key = tmp_str;
            miginfo.request_port.value = (void*)strlen(tmp_str);
            *tmp_str2 = tmp_char;
        }
    }
    
    //Extract MIG Routine Info: Value of msgh_reply_port
    const char *msgh_reply_port_patt = "InP->Head.msgh_reply_port = ";
    tmp_str = strstr(migroutine_start, msgh_reply_port_patt);
    if(tmp_str){
        tmp_str += strlen(msgh_reply_port_patt);
        tmp_str2 = strstr(tmp_str, ";");
        if(tmp_str2){
            tmp_char = *tmp_str2;
            *tmp_str2 = '\0';
            miginfo.reply_port.key = tmp_str;
            miginfo.reply_port.value = (void*)strlen(tmp_str);
            *tmp_str2 = tmp_char;
        }
    }
    
    //Extract MIG Routine Info: Value of msgh_id
    const char *msgh_id_patt = "InP->Head.msgh_id = ";
    tmp_str = strstr(migroutine_start, msgh_id_patt);
    if(tmp_str){
        tmp_str += strlen(msgh_id_patt);
        tmp_str2 = strstr(tmp_str, ";");
        if(tmp_str2){
            tmp_char = *tmp_str2;
            *tmp_str2 = '\0';
            miginfo.msghid = atoi(tmp_str);
            *tmp_str2 = tmp_char;
        }
    }
    
    //Extract MIG Routine Info: The Arguments
    for(int i=0; i<arr_routine_args->count; i++){
        arr_entry_t *entry_funcargs = arr_getByIndex(arr_routine_args, i);
        
        if(!miginfo.arr_args)
            miginfo.arr_args = arr_alloc();
        
        Arg_Info *buf_arginfo = malloc(sizeof(Arg_Info));
        bzero(buf_arginfo, sizeof(Arg_Info));
        
        arr_add(miginfo.arr_args, buf_arginfo, NULL);
        
        buf_arginfo->full_name.key = entry_funcargs->key;
        buf_arginfo->full_name.value = entry_funcargs->value;
        
        //Print full name of argument
        //printf("|%.*s|\n", (int)entry_funcargs->value, entry_funcargs->key);
        
        tmp_char = ((char*)entry_funcargs->key)[(size_t)entry_funcargs->value];
        ((char*)entry_funcargs->key)[(size_t)entry_funcargs->value] = '\0';
        
        arr_t *arr_argtypes = NULL, *arr_argnames = NULL;
        regex_grouping(entry_funcargs->key, "(.*?\\s\\**?)([a-zA-Z0-9_]*?).*", 3, NULL, &arr_argtypes, &arr_argnames);
        ((char*)entry_funcargs->key)[(size_t)entry_funcargs->value] = tmp_char;
        if(!arr_argtypes || !arr_argnames){
            //This regex doesn'ot support variable in function-pointer type, need update if encountered.
            printf("Error: update regex for function-ptr\n");
            exit(1);
        }
        
        buf_arginfo->type.key = ((arr_entry_t *)arr_getByIndex(arr_argtypes, 0))->key;
        buf_arginfo->type.value = ((arr_entry_t *)arr_getByIndex(arr_argtypes, 0))->value;
        //Remove blank at end
        for(uint32_t i=(uint32_t)buf_arginfo->type.value; i>0; i--){
            if(((char*)buf_arginfo->type.key)[i-1] == ' ')
                buf_arginfo->type.value --;
            else
                break;
        }
        
        buf_arginfo->name.key = ((arr_entry_t *)arr_getByIndex(arr_argnames, 0))->key;
        buf_arginfo->name.value = ((arr_entry_t *)arr_getByIndex(arr_argnames, 0))->value;
        
        arr_free(arr_argtypes);
        arr_free(arr_argnames);
        
        //Check whether in request/reply member list
        for(int i=0; i<2; i++){
            
            bool isRequestLoop = true;
            if(i == 0)
                isRequestLoop = true;
            else
                isRequestLoop = false;
            
            bool isConstru_struargs = false;
            
            if(isRequestLoop){
                if(!miginfo.arr_request_stru_args){
                    miginfo.arr_request_stru_args = arr_alloc();
                    isConstru_struargs = true;
                }
            }
            else{
                if(!miginfo.arr_reply_stru_args){
                    miginfo.arr_reply_stru_args = arr_alloc();
                    isConstru_struargs = true;
                }
            }
            
            arr_t *arr_tmpalias = isRequestLoop?arr_request_args:arr_reply_args;
            arr_t *arr_tmpalias2 = isRequestLoop?miginfo.arr_request_stru_args:miginfo.arr_reply_stru_args;
            
            //Further parsing in structure member
            bool is_msgh_body_within = false;
            for(int i=0; isConstru_struargs && i<arr_tmpalias->count; i++){
                
                arr_entry_t *entry_struarg = arr_getByIndex(arr_tmpalias, i);
                
                char tmp_char = ((char*)entry_struarg->key)[(size_t)entry_struarg->value];
                ((char*)entry_struarg->key)[(size_t)entry_struarg->value] = '\0';
                
                //Print raw structure member
                //printf("|%s|\n", entry_reqarg->key);
                const char *msgh_body_start_patt = "/* start of the kernel processed data */";
                const char *msgh_body_end_patt = "/* end of the kernel processed data */";
                
                if((strcmp(entry_struarg->key, msgh_body_start_patt) == 0) || (strcmp(entry_struarg->key, msgh_body_end_patt) == 0)){
                    ((char*)entry_struarg->key)[(size_t)entry_struarg->value] = tmp_char;
                    
                    is_msgh_body_within = !is_msgh_body_within;
                    continue;
                }
                
                Arg_Info *buf_struarginfo = malloc(sizeof(Arg_Info));
                bzero(buf_struarginfo, sizeof(Arg_Info));
                
                arr_add(arr_tmpalias2, buf_struarginfo, NULL);
                buf_struarginfo->full_name.key = entry_struarg->key;
                buf_struarginfo->full_name.value = entry_struarg->value;
                
                arr_t *arr_stru_vartypes = NULL;
                arr_t *arr_stru_varnames = NULL;
                arr_t *arr_stru_vararrcount = NULL;
                regex_grouping(entry_struarg->key, "(.*?\\s\\**?)([a-zA-Z0-9_]*?)[\\[]*?(.*)\\]*?;", 4, NULL, &arr_stru_vartypes, &arr_stru_varnames, &arr_stru_vararrcount);
                ((char*)entry_struarg->key)[(size_t)entry_struarg->value] = tmp_char;
                if(!arr_stru_vartypes || !arr_stru_varnames){
                    printf("ERROR\n");
                    exit(1);
                }
                
                arr_entry_t *entry_stru_vartype = arr_getByIndex(arr_stru_vartypes, 0);
                arr_entry_t *entry_stru_varname = arr_getByIndex(arr_stru_varnames, 0);
                
                if(is_msgh_body_within)
                    buf_struarginfo->isInMsgh_body = true;
                
                buf_struarginfo->type.key = entry_stru_vartype->key;
                buf_struarginfo->type.value = entry_stru_vartype->value;
                buf_struarginfo->name.key = entry_stru_varname->key;
                buf_struarginfo->name.value = entry_stru_varname->value;
                
                //Remove blank at end
                for(uint32_t i=(uint32_t)buf_struarginfo->type.value; i>0; i--){
                    if(((char*)buf_struarginfo->type.key)[i-1] == ' ')
                        buf_struarginfo->type.value --;
                    else
                        break;
                }
                
                arr_free(arr_stru_vartypes);
                arr_free(arr_stru_varnames);
                
                if(arr_stru_vararrcount){
                    arr_entry_t *entry_stru_vararrcount = arr_getByIndex(arr_stru_vararrcount, 0);
                    if(entry_stru_vararrcount->value != 0){
                        char tmp_char = ((char*)entry_stru_vararrcount->key)[(size_t)entry_stru_vararrcount->value];
                        ((char*)entry_stru_vararrcount->key)[(size_t)entry_stru_vararrcount->value] = '\0';
                        
                        buf_struarginfo->arrcount = atoi(entry_stru_vararrcount->key);
                        
                        ((char*)entry_stru_vararrcount->key)[(size_t)entry_stru_vararrcount->value] = tmp_char;
                    }
                    arr_free(arr_stru_vararrcount);
                }
                
                //Print variable type in Request structure
                //printf("|%.*s|\n", (int)entry_stru_vartype->value, entry_stru_vartype->key);
                
                //Print variable name in Request structure
                //printf("|%.*s|\n", (int)entry_stru_varname->value, entry_stru_varname->key);
                
                //printf("|%d %.*s|\n", isRequestLoop, (int)buf_struarginfo->name.value, buf_struarginfo->name.key);
                
                //Detect delta size
                if(isRequestLoop){
                    arr_t *arr_msd = regex_normal(migroutine_start, "msgh_size_delta =.*?\\((.*->)*?(.* )*?%.*s\\)", (int)buf_struarginfo->name.value, buf_struarginfo->name.key);
                    if(arr_msd){
                        arr_entry_t *entry_msdcode = arr_getByIndex(arr_msd, 0);
                        char *msdcode_start = entry_msdcode->key;
                        char *msdcode_end = strstr(msdcode_start, "InP =");
                        if(msdcode_end){
                            msdcode_end = strstr(msdcode_end, ";");
                            msdcode_end++;
                            
                            tmp_char = *msdcode_end;
                            *msdcode_end = '\0';
                            
                            buf_struarginfo->deltasize_adjust.key = msdcode_start;
                            buf_struarginfo->deltasize_adjust.value = (void*)strlen(msdcode_start);
                            
                            //printf("%s\n", msdcode_start);
                            *msdcode_end = tmp_char;
                        }
                        arr_free(arr_msd);
                    }
                }
                else{
                    uint32_t msdstr_len = snprintf(NULL, 0, "msgh_size_delta =.*(Out.P)->%.*s[) ].*?", (int)buf_struarginfo->name.value, buf_struarginfo->name.key);
                    char msdstr[msdstr_len + 1];
                    snprintf(msdstr, sizeof(msdstr), "msgh_size_delta =.*(Out.P)->%.*s[) ].*?", (int)buf_struarginfo->name.value, buf_struarginfo->name.key);
                    
                    arr_t *arr_msd = NULL;
                    arr_t *arr_msd_a = NULL;
                    regex_grouping(migroutine_reply_start, msdstr, 2, &arr_msd, &arr_msd_a);
                    if(arr_msd_a){
                        arr_entry_t *entry_msdcode = arr_getByIndex(arr_msd, 0);
                        arr_entry_t *entry_outP = arr_getByIndex(arr_msd_a, 0);
                        
                        char tmp_char = ((char*)entry_msdcode->key)[(uint32_t)(entry_msdcode->value)];
                        ((char*)entry_msdcode->key)[(uint32_t)(entry_msdcode->value)] = '\0';
                        
                        //Change all Out*P variety variable name to OutP
                        uint32_t outp_buf1_len = snprintf(NULL, 0, "%.*sOutP%s\n", (uint32_t)((char*)entry_outP->key - (char*)entry_msdcode->key), entry_msdcode->key, (char*)(entry_outP->key) + (uint32_t)(entry_outP->value));
                        char *outp_buf1 = malloc(outp_buf1_len + 1);
                        if(!outp_buf1){
                            printf("malloc issue\n");
                            exit(1);
                        }
                        snprintf(outp_buf1, outp_buf1_len + 1, "%.*sOutP%s\n", (uint32_t)((char*)entry_outP->key - (char*)entry_msdcode->key), entry_msdcode->key, (char*)(entry_outP->key) + (uint32_t)(entry_outP->value));
                        ((char*)entry_msdcode->key)[(uint32_t)(entry_msdcode->value)] = tmp_char;
                        
                        arr_t *arr_msd2 = regex_normal(entry_msdcode->key, "=\\s\\(__Reply \\*\\).*%.*s.*?;", (int)entry_outP->value, entry_outP->key);
                        if(!arr_msd2){
                            printf("ERROR\n");
                            exit(1);
                        }
                        
                        arr_entry_t *entry_cod2 = arr_getByIndex(arr_msd2, 0);
                        tmp_char = ((char*)entry_cod2->key)[(uint32_t)(entry_cod2->value)];
                        ((char*)entry_cod2->key)[(uint32_t)(entry_cod2->value)] = '\0';
                        
                        char *outp_a = (char*)memmem(entry_cod2->key, (uint32_t)entry_cod2->value, entry_outP->key, (uint32_t)entry_outP->value);
                        
                        //Change all Out*P variety variable name to OutP
                        uint32_t tmpoffset = 5;
                        uint32_t outp_buf2_len = snprintf(NULL, 0, "OutP = (%.*sOutP%s\n", (uint32_t)((char*)outp_a - (char*)entry_cod2->key) - tmpoffset, entry_cod2->key + tmpoffset, outp_a + (uint32_t)entry_outP->value);
                        char *outp_buf2 = realloc(outp_buf1, outp_buf1_len + outp_buf2_len + 1);
                        if(!outp_buf2){
                            printf("ERROR: 98DUYD3\n");
                            exit(1);
                        }
                        snprintf(outp_buf2 + outp_buf1_len, outp_buf2_len + 1, "OutP = (%.*sOutP%s", (uint32_t)((char*)outp_a - (char*)entry_cod2->key) - tmpoffset, entry_cod2->key + tmpoffset, outp_a + (uint32_t)entry_outP->value);
                        ((char*)entry_cod2->key)[(uint32_t)(entry_cod2->value)] = tmp_char;
                        
                        buf_struarginfo->deltasize_adjust.key = outp_buf2;
                        buf_struarginfo->deltasize_adjust.value = (void*)strlen(outp_buf2);
                        
                        arr_free(arr_msd2);
                        arr_free(arr_msd);
                        arr_free(arr_msd_a);
                    }
                }
            }
            
            //Link stru arg to mig args(function args)
            for(int i=0; i<arr_tmpalias2->count; i++){
                
                arr_entry_t *entry_struarg = arr_getByIndex(arr_tmpalias2, i);
                Arg_Info *struarginfo = entry_struarg->key;
                if(!struarginfo)
                    continue;
                
                if(memcmp(struarginfo->name.key, buf_arginfo->name.key, (size_t)(struarginfo->name.value > buf_arginfo->name.value?struarginfo->name.value: buf_arginfo->name.value))==0){
                    if(isRequestLoop)
                        buf_arginfo->link_struarg_request = struarginfo;
                    else
                        buf_arginfo->link_struarg_reply = struarginfo;
                    struarginfo->link_funcparm = buf_arginfo;
                }
            }
            
            //Check whether held by msgh_request_port
            if(miginfo.request_port.key && memcmp(miginfo.request_port.key, buf_arginfo->name.key, (size_t)(miginfo.request_port.value > buf_arginfo->name.value?miginfo.request_port.value: buf_arginfo->name.value))==0){
                buf_arginfo->isInRequest_port = true;
            }
            
            //Check whether held by msgh_reply_port
            if(miginfo.reply_port.key && memcmp(miginfo.reply_port.key, buf_arginfo->name.key, (size_t)(miginfo.reply_port.value > buf_arginfo->name.value?miginfo.reply_port.value: buf_arginfo->name.value))==0){
                buf_arginfo->isInReply_port = true;
            }
            
        }
    }
    
    arr_free(arr_routine_args);
    arr_free(arr_request_args);
    arr_free(arr_reply_args);
    
    //Continue to generate code with the info we have
    codegen_buildcode(&miginfo);
    
    //Release resources
    arr_t *loop_helper[] = {miginfo.arr_args, miginfo.arr_request_stru_args, miginfo.arr_reply_stru_args};
    for(int i=0; i<(sizeof(loop_helper)/sizeof(loop_helper[0])); i++){
        arr_t *tmp_arr = loop_helper[i];
        if(tmp_arr){
            for(int i=0; i<tmp_arr->count; i++){
                arr_entry_t *ent = arr_getByIndex(tmp_arr, i);
                
                if(ent->key)
                    free(ent->key);
                ent->key = NULL;
            }
            arr_free(tmp_arr);
        }
    }
    //End of Func
}

int main(int argc, const char * argv[]) {
    
    for(int i=0; i<2; i++){
        
        if(!PRINT_REQUEST_AND_REPLY_BOTH){
            i = 1;
            if(PRINT_REQEUST_ONLY_OTW_REPLY_ONLY)
                codegen_ipcstage = 1;
            else
                codegen_ipcstage = 3;
        }
        else{
            if(i!=0){
                if(codegen_switchcases)
                    arr_free(codegen_switchcases);
                codegen_switchcases = NULL;
                codegen_ipcstage = 3;
            }
        }
        
        heap_t *hv_file = file_read(TARGET_FILE_PATH);
        if(!hv_file){
            printf("file read failed\n");
            exit(1);
        }
        
        arr_t *arr_mig_routines = NULL;
        
        //Listing all MIG routine
        regex_grouping(hv_file->data, "/* Routine\\s(.*)\\s\\*/", 2, NULL, &arr_mig_routines);
        if(!arr_mig_routines){
            printf("Error: regex when listing all MIG routine\n");
            exit(1);
        }
        
        for(int i=0; i<arr_mig_routines->count; i++){
            arr_entry_t *entry_mig_routine = arr_getByIndex(arr_mig_routines, i);
            
#undef TMPMACRO
#define TMPMACRO(X) !memcmp(X, entry_mig_routine->key, strlen(X) > (size_t)entry_mig_routine->value?strlen(X):(size_t)entry_mig_routine->value)
            
#pragma mark TODO: Filter of function name for generate code
            
            if(!ENABLE_FUNCTION_NAME_FILTER || TMPMACRO("io_registry_create_iterator") /*|| TMPMACRO("Other Funcs")*/){
                
                //Print mig routine
                //printf("|%.*s|\n", (int)entry_mig_routine->value, entry_mig_routine->key);
                
                char *migroutine_start = entry_mig_routine->key;
                const char *migroutine_end_patt = "return KERN_SUCCESS;";
                char *migroutine_end = memmem(migroutine_start, strlen(migroutine_start), migroutine_end_patt, strlen(migroutine_end_patt));
                if(!migroutine_end){
                    printf("Error: migroutine_end\n");
                    exit(1);
                }
                *migroutine_end = '\0';
                
                char *migroutine_reply_start = NULL;
                arr_t *arr_reply = regex_normal((char*)hv_file->data, "kern_return_t __MIG_check__Reply__%.*s_t\\(.*?", (int)entry_mig_routine->value, entry_mig_routine->key);
                if(arr_reply){
                    arr_entry_t *ent = arr_getByIndex(arr_reply, 0);
                    if(ent)
                        migroutine_reply_start = ent->key;
                }
                
                const char *migroutine_reply_end_patt = "\n}\n";
                char *migroutine_reply_end = NULL;
                if(migroutine_reply_start){
                    migroutine_reply_end = memmem(migroutine_reply_start, strlen(migroutine_reply_start), migroutine_reply_end_patt, strlen(migroutine_reply_end_patt));
                    if(!migroutine_reply_end){
                        printf("Error migroutine_reply_end\n");
                        exit(1);
                    }
                    migroutine_reply_end += (strlen(migroutine_reply_end_patt)-1);
                    *migroutine_reply_end = '\0';
                }
                
                //Further parsing for each mig routine
                func_parse_request_routine(migroutine_start, migroutine_reply_start);
                
                *migroutine_end = migroutine_end_patt[0];
                *migroutine_reply_end = migroutine_reply_end_patt[strlen(migroutine_reply_end_patt)-1];
                //End of arr_mig_routines iteration
            }
        }
        arr_free(arr_mig_routines);
        
        codegen_laststep();
    }
    
    return 0;
}
