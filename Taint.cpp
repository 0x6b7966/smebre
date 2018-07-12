//
//  Jonathan Salwan - Copyright (C) 2013-08
// 
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
//
//  Note: Example 3 - http://shell-storm.org/blog/Taint-analysis-with-Pin/
//        Spread the taint in memory/registers and follow your data.
//

#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <list>

std::string lfaddr = "/tmp/mytaint.log";
std::list<UINT32> addressTainted;
std::list<REG> regsTainted;

INT32 Usage()
{
    cerr << "Ex 3" << endl;
    return -1;
}

bool checkAlreadyRegTainted(REG reg)
{
  list<REG>::iterator i;

  for(i = regsTainted.begin(); i != regsTainted.end(); i++){
    if (*i == reg){
      return true;
    }
  }
  return false;
}

VOID removeMemTainted(UINT32 addr)
{
  FILE *logfile;
  if ((logfile = fopen(lfaddr.c_str(), "a")) != NULL) {
    addressTainted.remove(addr);
    fprintf(logfile, "\t\t\t\t%08x is now freed\n", addr);
    //std::cout << std::hex << "\t\t\t" << addr << " is now freed" << std::endl;
    fclose(logfile);
  }

}

VOID addMemTainted(UINT32 addr)
{
  FILE *logfile;
  if ((logfile = fopen(lfaddr.c_str(), "a")) != NULL) {
    addressTainted.push_back(addr);
    fprintf(logfile, "\t\t\t\t%08x is now tainted\n", addr);
    //std::cout << std::hex << "\t\t\t" << addr << " is now tainted" << std::endl;
    fclose(logfile);
  }
}

bool taintReg(FILE *logfile, REG reg)
{
  if (checkAlreadyRegTainted(reg) == true){
    fprintf(logfile, "\t\t\t\t%s is already tainted\n", REG_StringShort(reg).c_str());
    //std::cout << "\t\t\t" << REG_StringShort(reg) << " is already tainted" << std::endl;
    return false;
  }

  switch(reg){

    //case REG_RAX:  regsTainted.push_front(REG_RAX);
    case REG_EAX:  regsTainted.push_front(REG_EAX); 
    case REG_AX:   regsTainted.push_front(REG_AX); 
    case REG_AH:   regsTainted.push_front(REG_AH); 
    case REG_AL:   regsTainted.push_front(REG_AL); 
         break;

    //case REG_RBX:  regsTainted.push_front(REG_RBX);
    case REG_EBX:  regsTainted.push_front(REG_EBX);
    case REG_BX:   regsTainted.push_front(REG_BX);
    case REG_BH:   regsTainted.push_front(REG_BH);
    case REG_BL:   regsTainted.push_front(REG_BL);
         break;

    //case REG_RCX:  regsTainted.push_front(REG_RCX); 
    case REG_ECX:  regsTainted.push_front(REG_ECX);
    case REG_CX:   regsTainted.push_front(REG_CX);
    case REG_CH:   regsTainted.push_front(REG_CH);
    case REG_CL:   regsTainted.push_front(REG_CL);
         break;

    //case REG_RDX:  regsTainted.push_front(REG_RDX); 
    case REG_EDX:  regsTainted.push_front(REG_EDX); 
    case REG_DX:   regsTainted.push_front(REG_DX); 
    case REG_DH:   regsTainted.push_front(REG_DH); 
    case REG_DL:   regsTainted.push_front(REG_DL); 
         break;

    //case REG_RDI:  regsTainted.push_front(REG_RDI); 
    case REG_EDI:  regsTainted.push_front(REG_EDI); 
    case REG_DI:   regsTainted.push_front(REG_DI); 
    //case REG_DIL:  regsTainted.push_front(REG_DIL); 
         break;

    //case REG_RSI:  regsTainted.push_front(REG_RSI); 
    case REG_ESI:  regsTainted.push_front(REG_ESI); 
    case REG_SI:   regsTainted.push_front(REG_SI); 
    //case REG_SIL:  regsTainted.push_front(REG_SIL); 
         break;

    default:
      fprintf(logfile, "\t\t\t\t%s can't be tainted\n", REG_StringShort(reg).c_str());
      //std::cout << "\t\t\t" << REG_StringShort(reg) << " can't be tainted" << std::endl;
      return false;
  }
  fprintf(logfile, "\t\t\t\t%s is now tainted\n", REG_StringShort(reg).c_str());
  //std::cout << "\t\t\t" << REG_StringShort(reg) << " is now tainted" << std::endl;
  return true;
}

bool removeRegTainted(REG reg)
{
  switch(reg){

    //case REG_RAX:  regsTainted.remove(REG_RAX);
    case REG_EAX:  regsTainted.remove(REG_EAX);
    case REG_AX:   regsTainted.remove(REG_AX);
    case REG_AH:   regsTainted.remove(REG_AH);
    case REG_AL:   regsTainted.remove(REG_AL);
         break;

    //case REG_RBX:  regsTainted.remove(REG_RBX);
    case REG_EBX:  regsTainted.remove(REG_EBX);
    case REG_BX:   regsTainted.remove(REG_BX);
    case REG_BH:   regsTainted.remove(REG_BH);
    case REG_BL:   regsTainted.remove(REG_BL);
         break;

    //case REG_RCX:  regsTainted.remove(REG_RCX); 
    case REG_ECX:  regsTainted.remove(REG_ECX);
    case REG_CX:   regsTainted.remove(REG_CX);
    case REG_CH:   regsTainted.remove(REG_CH);
    case REG_CL:   regsTainted.remove(REG_CL);
         break;

    //case REG_RDX:  regsTainted.remove(REG_RDX); 
    case REG_EDX:  regsTainted.remove(REG_EDX); 
    case REG_DX:   regsTainted.remove(REG_DX); 
    case REG_DH:   regsTainted.remove(REG_DH); 
    case REG_DL:   regsTainted.remove(REG_DL); 
         break;

    //case REG_RDI:  regsTainted.remove(REG_RDI); 
    case REG_EDI:  regsTainted.remove(REG_EDI); 
    case REG_DI:   regsTainted.remove(REG_DI); 
    //case REG_DIL:  regsTainted.remove(REG_DIL); 
         break;

    //case REG_RSI:  regsTainted.remove(REG_RSI); 
    case REG_ESI:  regsTainted.remove(REG_ESI); 
    case REG_SI:   regsTainted.remove(REG_SI); 
    //case REG_SIL:  regsTainted.remove(REG_SIL); 
         break;

    default:
      return false;
  }
  //fprintf(logfile, "\t\t\t%s is now freed\n", REG_StringShort(reg).c_str());
  //std::cout << "\t\t\t" << REG_StringShort(reg) << " is now freed" << std::endl;
  return true;
}

VOID ReadMem(UINT32 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT32 memOp)
{
  list<UINT32>::iterator i;
  UINT32 addr = memOp;
  
  if (opCount != 2)
   return;

  FILE *logfile;
  if ((logfile = fopen(lfaddr.c_str(), "a")) != NULL) {

    for(i = addressTainted.begin(); i != addressTainted.end(); i++){
        if (addr == *i){
          fprintf(logfile, "[READ in %08x]\t%08x: %s\n", addr, insAddr, insDis.c_str());
          
          //std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
          taintReg(logfile, reg_r);
          fclose(logfile);
          return;
        }
    }
    /* if mem != tained and reg == taint => free the reg */
    if (checkAlreadyRegTainted(reg_r)){
      fprintf(logfile, "[READ in %08x]\t%08x: %s\n", addr, insAddr, insDis.c_str());
          
      //std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
      removeRegTainted(reg_r);
    }
    fclose(logfile);
  }
  
}

VOID WriteMem(UINT32 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT32 memOp)
{
  list<UINT32>::iterator i;
  UINT32 addr = memOp;

  if (opCount != 2)
    return;

  FILE *logfile;
  if ((logfile = fopen(lfaddr.c_str(), "a")) != NULL) {

    for(i = addressTainted.begin(); i != addressTainted.end(); i++){
        if (addr == *i){
          fprintf(logfile, "[WRITE in %08x]\t%08x: %s\n", addr, insAddr, insDis.c_str());
          //std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
          if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
            removeMemTainted(addr);
          fclose(logfile);
          return;
        }
    }
    if (checkAlreadyRegTainted(reg_r)){
      fprintf(logfile, "[WRITE in %08x]\t%08x: %s\n", addr, insAddr, insDis.c_str());
      //std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
      addMemTainted(addr);
    }
    fclose(logfile);
  }
}

VOID spreadRegTaint(UINT32 insAddr, std::string insDis, UINT32 opCount, REG reg_r, REG reg_w)
{
  if (opCount != 2)
    return;

  FILE *logfile;
  if ((logfile = fopen(lfaddr.c_str(), "a")) != NULL) {

    if (REG_valid(reg_w)){
      if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))){
        fprintf(logfile, "[REMOVE<-]\t\t%08x: %s\n", insAddr, insDis.c_str());
        //fprintf(logfile, "\t\t\toutput: %s | input: %s\n", REG_StringShort(reg_w).c_str(), (REG_valid(reg_r) ? REG_StringShort(reg_r).c_str() : "constant"));
        
        //std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
        //std::cout << "\t\t\toutput: "<< REG_StringShort(reg_w) << " | input: " << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") << std::endl;
        removeRegTainted(reg_w);
      }
      else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)){
        fprintf(logfile, "[SPREAD<-]\t\t%08x: %s\n", insAddr, insDis.c_str());
        //fprintf(logfile, "\t\t\toutput: %s | input: %s\n", REG_StringShort(reg_w).c_str(), REG_StringShort(reg_r).c_str());
        
        //std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
        //std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: "<< REG_StringShort(reg_r) << std::endl;
        taintReg(logfile, reg_w);
      }
    }
    fclose(logfile);
  }
}

VOID followData(UINT32 insAddr, std::string insDis, REG reg)
{
  if (!REG_valid(reg))
    return;

  FILE *logfile;
  if ((logfile = fopen(lfaddr.c_str(), "a")) != NULL) {

    if (checkAlreadyRegTainted(reg)){
      fprintf(logfile, "[CHECK]\t\t\t%08x: %s\n", insAddr, insDis.c_str());
      //std::cout << "[FOLLOW]\t\t" << insAddr << ": " << insDis << std::endl;
    }
    fclose(logfile);
  }
}

VOID Instruction(INS ins, VOID *v)
{
  //std::cout << INS_Disassemble(ins) << std::endl;
  //std::cout << INS_OperandCount(ins) << std::endl;
  //Memory(Read), Register
  if (INS_OperandCount(ins) == 2 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        IARG_UINT32, INS_OperandReg(ins, 0),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
  //Memory(Write, Register)
  else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        IARG_UINT32, INS_OperandReg(ins, 1),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
  else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        IARG_UINT32, INS_RegR(ins, 0),
        IARG_UINT32, INS_RegW(ins, 0),
        IARG_END);
  }
  
  if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)followData,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_UINT32, INS_RegR(ins, 0),
        IARG_END);
  }
}

static unsigned int tryksOpen;

#define TRICKS(){if (tryksOpen++ == 0)return;}

static void hexdump(FILE *logfile, unsigned char* byte_arr, int len){
  int i = 0;
  if(len > 0){
    while (i < len) (void)fprintf(logfile, "%02x", (unsigned)byte_arr[i++]);
    fprintf(logfile, "\n");
  }
}

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  unsigned int i;
  unsigned char *byte_arr;
  UINT32 readfd, start, size;
  FILE *logfile;

  if (PIN_GetSyscallNumber(ctx, std) == __NR_read){

      TRICKS(); /* tricks to ignore the first open */

      readfd = PIN_GetSyscallArgument(ctx, std, 0);
      if(readfd <= 0x1e) return;

      start = static_cast<UINT32>((PIN_GetSyscallArgument(ctx, std, 1)));
      size  = static_cast<UINT32>((PIN_GetSyscallArgument(ctx, std, 2)));

      for (i = 0; i < size; i++)
        addressTainted.push_back(start+i);
      
      if ((logfile = fopen(lfaddr.c_str(), "a")) != NULL) {
        fprintf(logfile, "[TAINT]\t\t\tbytes tainted from %08x to %08x (via read fd 0x%x)\n", start, start+size, readfd);
        byte_arr = (unsigned char*)start;
        hexdump(logfile, byte_arr, size);
        //std::cout << "[TAINT]\t" << "fd : " << readfd << "\tbytes tainted from " << std::hex << "0x" << start << " to 0x" << start+size << " (via read)"<< std::endl;
        fclose(logfile);
      }
  }
}

int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }
    
    PIN_SetSyntaxIntel();
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();
    
    return 0;
}

