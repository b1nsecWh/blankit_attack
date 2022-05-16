import re
import logging
import subprocess

import angr

logging.getLogger('cle').setLevel(logging.CRITICAL)
logging.getLogger('barf.analysis.graphs.controlflowgraph').setLevel(logging.CRITICAL)
logging.getLogger('barf.arch').setLevel(logging.CRITICAL)
logging.getLogger('angr.analyses').setLevel(logging.CRITICAL)
logging.getLogger('pyvex.lifting.libvex').setLevel(logging.CRITICAL)
logging.getLogger('claripy').setLevel(logging.CRITICAL)
logging.getLogger('angr.state_plugins').setLevel(logging.CRITICAL)

    
def get_binary_import_apis(binary):
    symbol_dict={}
    
    p=angr.Project(binary)

    for key,value in p.loader.main_object.imports.items():
        if value.symbol.is_function:
            lib=value.symbol.resolvedby.owner.binary
            if lib not in symbol_dict.keys():
                symbol_dict[lib]=[]
            symbol_dict[lib].append(key)
    return symbol_dict

def analyses_lib_api(lib,api):

    p=angr.Project(lib)
    
    imports_addr={x.relative_addr:{'name':x.symbol.name,  'lib':x.symbol.resolvedby.owner.binary if x.symbol.resolvedby else None} for x in p.loader.main_object.imports.values()}
    imports_name={x.symbol.name:  {'addr':x.relative_addr,'lib':x.symbol.resolvedby.owner.binary if x.symbol.resolvedby else None} for x in p.loader.main_object.imports.values()}
    # api
    api=p.loader.main_object.get_symbol(api)#.relative_addr

    sub_apis=set()                   #

    try:
        cfg=p.analyses.CFGEmulated(context_sensitivity_level=0,resolve_indirect_jumps=False,call_depth=5,starts=[api.rebased_addr])

        root=cfg.model.get_all_nodes(api.rebased_addr)[0] 
        successors=cfg.model.get_all_successors(root)
        sub_apis.add(api.name)
        for successor in successors:
            print(successor)
            if not successor.name: continue
            if successor.name in imports_name.keys(): continue
            # if subprocess.is_function():
            sub_apis.add(successor.name.split("+")[0].split("-")[0]) 
    except:
        pass

    return sub_apis



if __name__ == "__main__":
    binary='example'

    lib_apis_dict=get_binary_import_apis(binary)
    print(lib_apis_dict)

    with open("api_subfunction.txt","a") as f:
        for lib, apis in lib_apis_dict.items():
            print("="*20+"[",lib,"]"+"="*20)
            for i,api in enumerate(apis):
                if "main" in api: continue
                if "printf" == api: continue
                if "malloc" == api: continue
                print("[{}:\t{}] CFG analysis for \033[0;33;40m{}\033[0m".format(len(apis),i,api))
                sub_apis=analyses_lib_api(lib,api)
                print("{}:{}".format(api,";".join(list(sub_apis))))
                f.write("{}:{}\n".format(api,";".join(list(sub_apis))))
