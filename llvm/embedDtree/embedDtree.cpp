
#include <fstream>
#include <sstream>
#include "llvm/ADT/Statistic.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include <llvm/IR/Constants.h>
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/IteratedDominanceFrontier.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Analysis/LoopInfo.h"
#include <unordered_set>

using namespace std;
using namespace llvm;


#define DEBUG_TYPE "embedDtree"

#define WINDOW_SIZE 10
#define MIN_RDF_P 2 
#define MAX_RDF_P 11
#define MIN_F_ARG_P 12
#define MAX_F_ARG_P  21


namespace{
  struct embedDtree : public FunctionPass {

    static char ID;
    static unsigned int CIcounter;
    static int rdfIDCounter;
    static int funcIDCounter;
    LLVMContext *C;
    Module *thisModule;
    Type *int32Ty;

    SmallPtrSet<BasicBlock *, 16> needRDFofBBs;

    map<BasicBlock*, unsigned int > basicBlock_id_map;
    map<string, vector<string>> dtree;
    map<string, int > rdf_id_map;
    map<Instruction*, set<BasicBlock*>> instruction_to_rdf_succ_map;
    map<Instruction *, AllocaInst*> argI_to_rdfFlag_map;
    map< int,    std::string> global_id2string_map;
    map< std::string,    int> global_string2id_map;
    map< int ,           int> stringId_2counter_map;
    map<Instruction*, int> mCallSiteID;
    map<std::string, unsigned int > funcName_id_map;

    std::unordered_set<std::string > applicationFunctions;
    LoopInfo *LI;
    Function *instrFunc_Pred;

    embedDtree()  : FunctionPass(ID){}

    bool doInitialization(Module &M) override{
      errs()<<">>>>>>>>>>>>>>>>>>>>>>>>>>>initialization<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n";
      C = &M.getContext();
      thisModule = &M;

      /* travel application functions, to get all callsite*/
      errs()<<"[1] Get Callsite:\n";
      errs()<<"\tid\tcallsite\n";
      errs()<<"\t--\t--------\n";
      for(auto &f : M){
        if(f.isDeclaration()) continue;
      
        if (f.hasName() && !f.isDeclaration()) {
          // errs()<<"function::"<<f.getName();
          // errs()<<"\n";
          if (f.hasName()) applicationFunctions.insert(f.getName());
        }
        /* Basic Block */
        for(auto &b : f){
          /* Instruction */
          for(auto &i : b){
            // call site ?
            CallInst *CI = dyn_cast<CallInst>(&i);
            if(CI){
              Function *calledf = CI->getCalledFunction();
              if (calledf == NULL) continue;
              if (calledf->isIntrinsic()) continue;

              //TODO: simplefy, not to record the function that are not in paper
              if (!strcmp(calledf->getName().str().c_str(),"printf")) continue;
              if (!strcmp(calledf->getName().str().c_str(),"__isoc99_scanf")) continue;
              if (!strcmp(calledf->getName().str().c_str(),"malloc")) continue;

              if (mCallSiteID.find(CI) == mCallSiteID.end()) {
                mCallSiteID[&i] = ++CIcounter;
                errs()<<"\t"<<CIcounter<<"\t"<< calledf->getName() << "\n";
              }
            }
          }
        }



      }

      /* paramMap is actually not used, we removed it*/

      /* read function trace information? not sure*/
      /* Note: The purpose of string2id_map.csv seems to 
         be different in embedDtree.cpp and decrypt_probe.cpp.*/
      errs()<<"\n[2] Read string2id map:\n";
      errs()<<"\tid\tfunctions\t<counterId>\n";
      errs()<<"\t--\t---------\t-----------\n";
      int counter_strdID = 0;
      ifstream func2idmap;
      func2idmap.open("../data/string2id_map.csv");
      if(func2idmap.is_open()){
        string line;
        while(getline(func2idmap,line)){
          if (line.empty()){
            continue;
          }
          stringstream ss(line);
          ss>>ws;//skip whitespaces
          string token, funcName;
          int id=0;
          if (getline(ss, token, ',')){
            funcName = token;
          }
          if (getline(ss, token, ',')){
            id = stoi(token);
          }
          global_id2string_map[id] = funcName;
          global_string2id_map[funcName] = id;
          stringId_2counter_map[id] = ++counter_strdID;
          errs()<<"\t["<<id<<"]\t"<<funcName<<" :counter=<"<<counter_strdID<<">\n";

          while (getline(ss, token, ',')){
            errs()<<"\t token for func2id:"<<token<<":";
          }
        }
      }
      func2idmap.close();

      /* read function name to ID map */
      errs()<<"\n[3] Read Function name id:\n";
      errs()<<"\tid\tFunction Name\n";
      errs()<<"\t--\t-------------\n";
      func2idmap.open("../data/funcName_id_map.csv");
      if(func2idmap.is_open()){
        string line;
        while(getline(func2idmap,line)) {
          if (line.empty()){
            continue;
          }
          stringstream ss(line);
          ss>>ws;//skip whitespaces
          string token, funcName;
          int id=0;
          if (getline(ss, token, ',')){
            funcName = token;
          }
          if (getline(ss, token, ',')){
            id = stoi(token);
          }
          funcName_id_map[funcName] = id;
          errs()<<"\t"<<id<<"\t"<<funcName<<"\n";

          while (getline(ss, token, ',')){
            errs()<<"\n token for func2id:"<<token<<":";
          }
        }
      }
      func2idmap.close();

      /* read decision tree */
      errs()<<"\n[4] Read Decision Tree:\n";
      errs()<<"\t()\tNode\t\tcontent\n";
      errs()<<"\t--\t----\t\t-------------------------\n";
      ifstream fdtree;
      fdtree.open("../data/decisionTree");
      if(fdtree.is_open()){
        string line;
        while(getline(fdtree,line)){
          if (line.empty()){
            continue;
          }
          stringstream ss(line);
          ss>>ws;//skip whitespaces
          string node;
          getline(ss, node, '-');
          string iforleaf;
          getline(ss, iforleaf, '.');
          // if
          if(iforleaf.compare("if") == 0){
            string cond;
            getline(ss, cond, ':');
            string true_branch;
            getline(ss, true_branch, ';');
            string elseDummy;
            getline(ss, elseDummy, ':');
            string false_branch;
            getline(ss, false_branch, ';');
            //errs()<<"\t [cond] "<<node<<": ["<<cond<<","<<true_branch<<","<<false_branch<<"]\n";
            dtree[node] = {cond, true_branch, false_branch};
          }else{
            auto pos = line.find("=");
            string leafPred = line.substr(pos+1,string::npos);
            //errs()<<"\t [leaf] "<<node<<":"<<leafPred<<"\n";
            dtree[node] = {leafPred};
          }

        }
      }
      fdtree.close();

      for (auto a: dtree) {
        errs()<<"\t()\t"<<a.first<<"\t\t";
        for (auto b: a.second ) {
          errs()<<"str:"<<b<<" ";
        }
        errs()<<"\n";
      }
      return false;
    }

    bool runOnFunction(Function &F) override{
      bool bRet = false;

      BasicBlock *firstBB= nullptr;
      if(F.isDeclaration())
        return false;
      errs()<<"========================[fucntion: "<<F.getName()<<"]==========================\n";

      LI  = &getAnalysis<LoopInfoWrapperPass>().getLoopInfo();

      int32Ty = Type::getInt32Ty(*C );
      vector<Instruction*> callInsts;

      /*-----------------record callsite----------------*/
      errs()<<"[1] get all callsite:"<<"\n";
      /* basic block*/
      for(auto &b : F){
        if (firstBB==nullptr)
          firstBB = &b;
        /* instruction */
        for(auto &i : b){
          // recoird callsite instruction
          CallSite CS(&i);
          if(CS){
            Function *calledf = CS.getCalledFunction();

            if (calledf == NULL) continue;
            if (calledf->isIntrinsic()) continue;
            if (!calledf->hasName()) continue;

            //TODO: simplefy, not to record the function that are not in paper
            if (!strcmp(calledf->getName().str().c_str(),"printf")) continue;
            if (!strcmp(calledf->getName().str().c_str(),"__isoc99_scanf")) continue;
            if (!strcmp(calledf->getName().str().c_str(),"malloc")) continue;

            errs()<<"\t Pushing::"<<calledf->getName()<<"\n";
            errs().flush();
            callInsts.push_back(&i);
            bRet = true;
          }

        }
      }

      /*----------------insert DecisionTree------------*/
      errs()<<"[2] insert decision tree:"<<"\n";
      /* call site */
      for(auto &CI : callInsts){
        CallSite CS(CI);

        Function *fi = CS.getCalledFunction();
        // errs()<<"\tGot :"<<fi->getName()<<"\n";;
        if (applicationFunctions.find(fi->getName()) != applicationFunctions.end() ){
          // errs()<<"\t skipping::";
          continue;
        }
        
        errs()<<"\t[+] Instrumenting Function :"<<fi->getName()<<"\n";
        insertDtree(CS,fi->getName().str());
        bRet=true;
      }

      /*---------------instrument  RDF-----------------*/
      errs()<<"[3] instrument  RDF:"<<"\n";
      /* call site */
      for(auto &CI : callInsts){
        
        CallInst *callIns = dyn_cast<CallInst> (CI);
        if (callIns == NULL) continue;
        Function *calledF=    callIns->getCalledFunction();
        if (calledF == NULL) continue;
        if (calledF->isIntrinsic()|| !calledF->hasName() ) continue;
        if (callIns->getDereferenceableBytes(0)) continue;
        if (dyn_cast<InvokeInst>(callIns ) ) continue;

        errs()<<"\tGot :"<<calledF->getName()<<"\n";
        unsigned int numArgs = callIns->getNumArgOperands();
        /* args */
        for (unsigned int i=0; i<numArgs;i++){
          Value * argV = callIns->getArgOperand(i);

          /* arg instruction */
          if (Instruction *argI = dyn_cast<Instruction>(argV) ) {
            IRBuilder<> builder(&*firstBB->getFirstInsertionPt());

            /* creat alloca to store RDF */
            AllocaInst *alloca = builder.CreateAlloca(int32Ty);
            argI_to_rdfFlag_map[argI] = alloca;

            /* get RDF bb block */
            set<BasicBlock*> temp;
            if (instruction_to_rdf_succ_map.find(argI) != instruction_to_rdf_succ_map.end())
              temp = instruction_to_rdf_succ_map[argI];
            needRDFofBBs.clear();

            /* track basic RDF */
            trackReachingDefs(argI);
            SmallVector<BasicBlock *, 32> RDFBlocks;
            PostDominatorTree &PDT = getAnalysis<PostDominatorTreeWrapperPass>().getPostDomTree();

            computeControlDependence(PDT, needRDFofBBs, RDFBlocks);

            for (auto BB : RDFBlocks ){
              TerminatorInst *ti = BB->getTerminator();
              for (BasicBlock *succBB : ti->successors()){
                temp.insert(succBB);

                std::string rdf_s = BB->getName().str() +"_"+succBB->getName().str();
           
                if (rdf_id_map.find(rdf_s) == rdf_id_map.end())
                  rdf_id_map[rdf_s] = ++rdfIDCounter;
            
                IRBuilder<> builder(&*succBB->getFirstInsertionPt());

                Value *rdfID_v = ConstantInt::get(int32Ty, rdf_id_map[rdf_s]); 
                builder.CreateStore(rdfID_v, alloca);
              }
            }
            instruction_to_rdf_succ_map[argI] = temp;
          }
        }
      }

      callInsts.clear();
      return bRet;
    }

    void insertDtree(CallSite &CS,string name){
      string firstNode;
      for (auto a: dtree) {
        if (a.first.find("node") != string::npos) {
          firstNode = a.first;
          // errs()<<"\n+"<<firstNode<<"\n";
          break;
        }
      }
      recursiveIfElseTree(CS.getInstruction(),firstNode, CS);
    }

    void recursiveIfElseTree(Instruction *insBef, string node, CallSite &CS){
      int numArgs = CS.getNumArgOperands();
      vector<string> predicate = dtree[node];

      errs()<<"\t\t> "<<node;

      /*0.0: Branch*/
      if(predicate.size() > 2){
        errs()<<" |if";

        string cond = predicate[0];  
        string if_node = predicate[1]; 
        string else_node = predicate[2];
        stringstream streamCond(cond);
        int pindex;
        float fvalue; 
        int intVal;
        string dummyparam, dummypred;
        streamCond >> dummyparam >> pindex >> dummypred >> fvalue;
        intVal = fvalue;
        errs()<<"\t[param]: "<<dummyparam<<"\t[pindex]:" <<pindex<<"\t[pred]:"<<dummypred<<"\t[fvalue]:"<<fvalue;
        errs()<<"\tthen{"<<if_node<<"}\telse{"<<else_node<<"}\n";

        Value *vfArg = nullptr ; 
        int const_value = -1;
        bool is_const = false;

        /*1 different judgment conditions, according to pindex*/
        if(isPindexValid(pindex, numArgs)) {

          /*1.1: entry function*/
          if (pindex == 1) {//entryfunc
            string fname = CS.getCalledFunction()->getName();
            int funcID;

            if (funcName_id_map.find(fname) != funcName_id_map.end()){
              funcID = funcName_id_map[fname] ;
            }else if (global_string2id_map.find(fname) != global_string2id_map.end()){
              funcID = global_string2id_map[fname];
            }else{
              funcName_id_map[fname] = ++funcIDCounter;
              funcID = funcIDCounter;
            }

            vfArg = ConstantInt::get( int32Ty, funcID); /* funcID */
            const_value = funcID;
            is_const = true;
          /*1.2: callsite*/
          }else if(pindex == 0){
            int callSiteID = mCallSiteID[CS.getInstruction()]; /* callsite ID*/
            vfArg = ConstantInt::get( int32Ty, callSiteID);
            const_value = callSiteID;
            is_const = true;
          /*1.3: RDF*/
          }else if(pindex <MIN_F_ARG_P){
            unsigned argnum = pindex - MIN_RDF_P;
            Value *vArg = CS.getArgOperand(argnum); 

            if (Instruction *argI = dyn_cast<Instruction>(vArg) ) {
              if (argI_to_rdfFlag_map.find(argI) != argI_to_rdfFlag_map.end() ){
                AllocaInst *ptr = argI_to_rdfFlag_map[argI];
                if (isa<PHINode>(argI))
                  argI = &*argI->getParent()->getFirstInsertionPt();
                IRBuilder<> builder(argI );
                vfArg = builder.CreateLoad(ptr);
              }
             }
          /*1.4: argument*/
          }else if (pindex < MAX_F_ARG_P){
            
            unsigned argnum = pindex - MIN_F_ARG_P;
            Value *funcArg = CS.getArgOperand(argnum);
            Value *castedArg = nullptr;
            IRBuilder<> builder(insBef);

            if (funcArg != NULL ) {
              
              if (funcArg->getType()->isFloatTy()||funcArg->getType()->isDoubleTy() )
                castedArg = builder.CreateFPToSI(funcArg, int32Ty ); 
              else if ( funcArg->getType()->isIntegerTy() )
                castedArg = builder.CreateIntCast(funcArg , int32Ty, true);
              /*Note: The author of BlankIt does not handle string here. We have expanded it*/
              else if ( funcArg->getType()->isPointerTy())
                castedArg = builder.CreatePointerCast(funcArg , int32Ty);
              vfArg = castedArg;
            }
          }
        }else{//if invalid then just -1
          Value *p1 = ConstantInt::get(int32Ty, -1);
          vfArg = p1;
          const_value = -1;
          is_const = true;
        }

        /*2 judement & do last node*/
        if (vfArg != nullptr){
          bool compare_const_result ; 
          /* const vs. const  (i.e, FuncID)*/
          if(is_const){
            // compare result
            compare_const_result = const_value <= fvalue;
            errs()<<"\t\t\t└--> const vs. const: "<<const_value<<"<="<<fvalue<<"="<<compare_const_result<<"\n";
            if(compare_const_result){
              recursiveIfElseTree(insBef, if_node, CS);
            }else{
              recursiveIfElseTree(insBef, else_node, CS);
            }
          /* var vs. const (i.e, argument)*/
          }else{
            Value *p2 = ConstantInt::get(int32Ty, fvalue);
            //the compare instraction in insert
            // for string pointer(check null, str==NULL), we changed SLE to ULE
            ICmpInst *fb = new  ICmpInst(insBef, ICmpInst::ICMP_ULE, vfArg, p2);

            errs()<<"\t\t\t└--> var vs. const: "<<*p2<<"<="<<vfArg<<"  insert:"<<*fb<<"\n";
            
            TerminatorInst *ThenTerm, *ElseTerm;
            SplitBlockAndInsertIfThenElse(fb, insBef, &ThenTerm, &ElseTerm);
            //if clause
            recursiveIfElseTree(ThenTerm, if_node, CS);
            //else clause
            recursiveIfElseTree(ElseTerm, else_node, CS);
          }
        }
      /*0.1:leaf*/
      }else{
        errs()<<" |else"<<"";
        IRBuilder<> builder(insBef);
        unsigned predId = stoi(dtree[node].at(0));

        errs()<<"\t[predict Id]:"<<predId<<"\n";

        vector<Value *> ArgsV;
        Type *int32Ty = IntegerType::getInt32Ty(*C );
        ArgsV.push_back(llvm::ConstantInt::get(int32Ty, predId,false));
        string funcTrace_str;

        if ( global_id2string_map.find(predId) != global_id2string_map.end() ) {
          funcTrace_str = global_id2string_map[predId];
        }

        if (funcTrace_str.compare(";") != 0){
          llvm::Type *ArgTypes_callsite[] = {int32Ty}	;
          string custom_instr_func_name = "blankit_predict";

          /* call blankit_predict function */
          instrFunc_Pred =dyn_cast<Function>(
            thisModule->getOrInsertFunction(custom_instr_func_name.c_str() ,
            FunctionType::get(int32Ty ,
            ArgTypes_callsite,
            false /*this is var arg func type*/) 
            )
          );

          builder.CreateCall(instrFunc_Pred ,ArgsV );
          errs()<<"\t\t\t└--> insert call blankit_predict() argv:"<<*ArgsV[0]<<"\n";
        }
      }
    }

    void getAnalysisUsage(AnalysisUsage &AU) const override {
      AU.addRequired<PostDominatorTreeWrapperPass>();
      AU.addRequired<DominatorTreeWrapperPass>();
      AU.addRequired<LoopInfoWrapperPass>();
    }

    void trackReachingDefs(Instruction *argI){
      // errs()<<"\t\t tracking:"<< *argI <<"\n"; 
      if (argI == NULL) return ;

      if (PHINode *phiDef= dyn_cast<PHINode>(argI)){
        errs() << "\t get phi node: "<<*phiDef<<"\n";
        for (auto defBB = phiDef->block_begin() , bbEnd = phiDef->block_end(); defBB != bbEnd ; defBB++){
          BasicBlock *bb = *defBB;
          needRDFofBBs.insert(bb);
        }
        return ;
      }

      for (int i= 0, num = argI->getNumOperands(); i < num ; i++) {
        Instruction *opI =dyn_cast<Instruction>(argI->getOperand(i));
        if (opI == NULL) continue;
        // errs()<<"\t\t\t opI:"<< *opI <<"\n"; 
        trackReachingDefs(opI);
      }
    }

    void computeControlDependence(PostDominatorTree &PDT, SmallPtrSet<BasicBlock *, 16> getRDFofBlocks, SmallVector<BasicBlock *, 32> &RDFBlocks) {
      ReverseIDFCalculator RDF(PDT) ;
      RDF.setDefiningBlocks(getRDFofBlocks );
      RDF.calculate(RDFBlocks);
    }

    void instrumentRDF(SmallVector<BasicBlock *, 32> RDFBlocks,unsigned  int callSite_num, int argument_num, string varName){
      if (RDFBlocks.size() == 0) return;
      std::set<BasicBlock* > basicBlock_done_set;
      Instruction *i = &*RDFBlocks[0]->getFirstInsertionPt();
      IRBuilder<> builder(i);
      AllocaInst *rdfFlag = builder.CreateAlloca(Type::getInt32Ty(*C));//, nullptr, varName);

      for (auto *BB : RDFBlocks) {
        DEBUG(dbgs() << "live control in: " <<* BB->getTerminator() << '\n');
        if (basicBlock_done_set.find(BB) != basicBlock_done_set.end()) continue; //if already instrumented goto next
        basicBlock_done_set.insert(BB);
        std::ostringstream parent_s;
        unsigned int bbID = basicBlock_id_map[BB];
        TerminatorInst *ti = BB->getTerminator();

        for (BasicBlock *succBB : ti->successors()){
          {
            Instruction * instrInstrumentBefore = &*succBB->getFirstInsertionPt();
            
            IRBuilder<> builder(instrInstrumentBefore);
            std::ostringstream s;
            
            unsigned int succ_bbID = basicBlock_id_map[succBB];
            s<<bbID<<"_"<<succ_bbID ;
            std::string rdf_s = s.str();
            if (rdf_id_map.find(rdf_s ) == rdf_id_map.end()) {
              rdf_id_map[rdf_s] = ++rdfIDCounter;
            }
            int rdf_id = rdf_id_map[rdf_s];
            Constant *p_init = ConstantInt::get(Type::getInt32Ty(*C), rdf_id);
            builder.CreateStore(p_init, rdfFlag);
          }
        }
      }
    }

    bool isPindexValid(int pindex, int numArgs)
    {
      if (pindex == 0 || pindex == 1) return true;  
      if (numArgs == 0 ) return false; 
      if (pindex >=MIN_RDF_P && pindex <=MAX_RDF_P)  
      {  if ( (numArgs - (pindex - MIN_RDF_P )) <= 0) return false;} 
      else if (pindex >=MIN_F_ARG_P  && pindex <=MAX_F_ARG_P)
      {  if ( (numArgs - (pindex - MIN_F_ARG_P )) <= 0) return false;}
      return true;
    }

  };
}


char embedDtree::ID = 0;
unsigned int embedDtree::CIcounter  = 0;
int embedDtree::rdfIDCounter  = 0;
int embedDtree::funcIDCounter=0;
static RegisterPass<embedDtree> X("embedDtree", "blankit backend");
