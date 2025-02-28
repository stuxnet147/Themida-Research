# 더미다(Themida) VM 분석  
  
## 목차  
  
1. [개요](#개요)  
2. [Themida VM 컨텍스트 구조 (`VM_CONTEXT`)](#themida-vm-컨텍스트-구조-vm_context)  
3. [핸들러 동작 원리 및 특징](#핸들러-동작-원리-및-특징)  
4. [핸들러 코드 분석 예시](#핸들러-코드-분석-예시)  
  
---  
  
## 개요  
  
Themida(또는 WinLicense 계열) 난독화 엔진은 **가상 머신(VM)**을 통해 바이너리 코드를 난독화 한다. 특히 x64 코드를 커스텀 바이트코드 형태로 바꿔서, 다양한 **가상 레지스터**, **가상 스택** 연산, **안티 디버깅** 등을 섞어 높은 난이도를 제공한다.  
  
역분석 과정의 핵심은 다음과 같다.  
  
1. **VM CONTEXT** 파악    
   - Themida VM 실행 시점에 실제 CPU 레지스터 / 플래그를 백업하고, 내부적으로 VM 전용 레지스터와 스택을 운영한다.  
2. **핸들러(Handler) 분석**    
   - 각 **가상화된 명령**(ADD, SUB, SHIFT, ROTATE, PUSH, POP, CALL, RET, …)을 처리하는 핸들러가 난독화되어 있다.  
3. **바이트코드 디스패치**    
   - VM 바이트코드(또는 워드 단위 opcode) + 핸들러 테이블로, 다음 핸들러 주소를 동적으로 계산한다.  
4. **리프팅(Devirtualization) 구현** 아이디어  
   - Python + Triton 등으로 **“바이트코드 → IR/원본 x86 코드”**를 반자동/자동으로 복원.  
  
---  
  
## Themida VM 컨텍스트 구조 (`VM_CONTEXT`)  
  
Themida VM은 **0x200 바이트 내외**의 VM CONTEXT를 사용한다. VM CONTEXT는 더미다 난독화 적용 과정에서 랜덤하게 오프셋이 정해진다.  
  
```c  
// 실제와 다름.  
struct VM_CONTEXT  
{  
  char VM_CONTEXT_START;  
  char field_1;  
  char field_2;  
  char field_3;  
  char field_4;  
  char field_5;  
  char field_6;  
  char field_7;  
  char field_8;  
  char field_9;  
  char field_A;  
  char field_B;  
  char field_C;  
  char field_D;  
  __unaligned __declspec(align(1)) __int64 vm_opnd_maybe_1;  
  __unaligned __declspec(align(1)) __int64 field_16;  
  __unaligned __declspec(align(1)) int vm_some_key2;  
  __unaligned __declspec(align(1)) __int64 vm_opaque_022;  
  __unaligned __declspec(align(1)) int field_2A;  
  __unaligned __declspec(align(1)) __int64 vReg_R11;  
  __unaligned __declspec(align(1)) __int64 vm_opaque_036;  
  __unaligned __declspec(align(1)) int vm_some_key1;  
  char vm_unknown_flag;  
  char field_43[12];  
  char vm_branch_flag_maybe;  
  __int64 vm_scratch_qword;  
  int vm_some_key3;  
  __unaligned __declspec(align(1)) __int64 field_5C;  
  __unaligned __declspec(align(1)) __int64 vm_opnd_maybe_2;  
  char vm_instruction_opcode5;  
  __unaligned __declspec(align(1)) __int16 vm_opaque_06D;  
  __unaligned __declspec(align(1)) __int64 vReg_R15;  
  char vm_opaque_077[12];  
  __unaligned __declspec(align(1)) __int64 vm_handlerScratch;  
  __unaligned __declspec(align(1)) __int16 vm_opaque_08B;  
  __unaligned __declspec(align(1)) __int64 vm_instruction_pointer;  
  __unaligned __declspec(align(1)) int vm_some_key5;  
  __unaligned __declspec(align(1)) __int64 vReg_R13;  
  char vm_instruction_opcode2;  
  __unaligned __declspec(align(1)) __int64 vm_some_key4;  
  __unaligned __declspec(align(1)) __int64 vReg_RDI;  
  __int16 field_B2;  
  int vm_some_key7;  
  char vm_instruction_opcode1;  
  __unaligned __declspec(align(1)) __int16 vm_some_key6;  
  __unaligned __declspec(align(1)) __int64 vReg_RBP;  
  __unaligned __declspec(align(1)) __int64 vReg_RBX;  
  __unaligned __declspec(align(1)) int pad;  
  __unaligned __declspec(align(1)) __int64 vm_left_value_1;  
  char vm_instruction_opcode4;  
  int vm_opaque_0D8;  
  __unaligned __declspec(align(1)) __int64 vReg_R9;  
  __unaligned __declspec(align(1)) __int64 vReg_R10;  
  __unaligned __declspec(align(1)) __int64 *vm_handlerTable;  
  int vm_opaque_0F4;  
  __int64 vReg_RCX;  
  __int64 vm_opaque_100;  
  int vm_handlerKey;  
  __unaligned __declspec(align(1)) __int64 vReg_R8;  
  __unaligned __declspec(align(1)) __int64 vReg_R14;  
  __unaligned __declspec(align(1)) __int64 vm_opnd_maybe_3;  
  __unaligned __declspec(align(1)) __int64 vReg_RAX;  
  char vm_instruction_opcode3;  
  char vm_opaque_12D[12];  
  __unaligned __declspec(align(1)) __int64 vReg_R12;  
  char vm_opaque_141[12];  
  __unaligned __declspec(align(1)) __int64 vReg_RSI;  
  char vm_operation_result_selector_maybe;  
  __int16 vm_opaque_156;  
  int vm_spinlock;  
  __unaligned __declspec(align(1)) __int64 vm_stack_pointer;  
  __unaligned __declspec(align(1)) __int64 vReg_RDX;  
  __unaligned __declspec(align(1)) __int64 vm_left_value_2;  
  char vm_opaque_174[140];  
};  
```  
  
- **`vm_handlerTable`**: 바이트코드 인덱스(또는 opcode)로부터 “핸들러” 주소를 가져올 때 사용.  
- **`vm_instruction_pointer`**: 현재 해석 중인 바이트코드 포인터?  
- **``vm_stack_pointer``**: vsp  
  
---  
  
## 더미다 동작 흐름 개요  
  
### VM ENTER:  
  
원본 컨텍스트를 스택에 푸시한다  
  
```  
// 간소화된 예시임. 실제와 다름.  
push r8  
push r9  
push r10  
push r11  
push r12  
push r13  
push r14  
push r15  
push rdi  
push rsi  
push rbp  
push rbx  
push rdx  
push rcx  
push rax  
push eflags  
push some_key  
push first_handler_offset  
push retaddr  
...  
```  
  
더미다는 단 한개의 VM CONTEXT 전역 변수를 모든 가상화 코드에서 공유하므로 진입 전에 스핀락을 설정한다.  
  
```  
.themida:1400931D0 loc_1400931D0:  
.themida:1400931D0  xor  eax, eax  
.themida:1400931D2  lock cmpxchg [rbx+rbp], ecx ;rbx는 스핀락 오프셋이고 rbp는 VM_CONTEXT의 시작주소  
.themida:1400931D7  jz  loc_1400931E4  
.themida:1400931DD  pause  
.themida:1400931DF  jmp  loc_1400931D0  
```  
  
스택에 푸시된 컨텍스트 정보를 VM CONTEXT로 옮긴다..  
  
```  
// 간소화된 예시임. 실제와 다름.  
pop     qword ptr [r9]	;eflags to VM_CONTEXT  
pop     qword ptr [r14]	;rax  
pop     qword ptr [r14]	;rcx  
pop     qword ptr [r15]	;rdx  
pop     qword ptr [r15]	;rbx  
pop     qword ptr [r15]	;rbp  
pop     qword ptr [rsi]	;rsi  
pop     qword ptr [rsi]	;rdi  
pop     qword ptr [r12]	;r15  
pop     qword ptr [r14]	;r14  
pop     qword ptr [r14]	;r13  
pop     qword ptr [r15]	;r12  
pop     qword ptr [r15]	;r11  
pop     qword ptr [r15]	;r10  
pop     qword ptr [r15]	;r9  
pop     qword ptr [r14]	;r8  
...  
```  
  
### VM HANDLER:  
  
간단히 말해서 이 과정에서는 바이트 코드를 해석하고 실행한다. 참고로 더미다의 바이트 코드는 바이트 배열이 아니다.  
  
예시 핸들러:  
  
```  
  // 간소화된 예시임. 실제와 다름.  
  // mov operation  
  if ( v0->vm_instruction_opcode1 == (char)0xEA )  
  {  
    v84 = v0->vm_opnd_maybe_1 + (v0->vm_some_key4 ^ v0->vm_opnd_maybe_2) - 0x6C1BFD75;  
    v85 = v0->vm_left_value_1 + v0->vm_opnd_maybe_3 + 0x2787FB21 - v0->vm_some_key4;  
    if ( v0->vm_instruction_opcode3 == 0x75 )  
      v84 = (char)v85;  
    if ( v0->vm_instruction_opcode3 == 0x76 )  
      v84 = (__int16)(LOWORD(v0->vm_left_value_1) + LOWORD(v0->vm_opnd_maybe_3) - 0x4DF - LOWORD(v0->vm_some_key4));  
    if ( v0->vm_instruction_opcode3 == 0x77 )  
      v84 = (unsigned int)v85;  
    v50 = v84 + v85;  
    __readeflags();  
    if ( v0->vm_operation_result_selector_maybe <= 0x8Eu )  
      v0->vm_left_value_1 = v84 ^ 0x2787FB21;  
    else  
      v0->vm_left_value_2 = v84 + 0x116ABA2E;  
  }  
    
  // shr operation  
  if ( v0->vm_instruction_opcode1 == 0x6D )  
  {  
    v214 = v0->vm_opnd_maybe_1 + (v0->vm_some_key4 ^ v0->vm_opnd_maybe_2) - 0x6C1BFD75;  
    v215 = v0->vm_left_value_1 + v0->vm_opnd_maybe_3 + 0x2787FB21 - v0->vm_some_key4;  
    v237 = *(_QWORD *)(&v0->VM_CONTEXT_START + *(unsigned __int16 *)(v0->vm_instruction_pointer + 0xB));  
    if ( v0->vm_instruction_opcode2 == (char)0xA2 )  
    {  
      __writeeflags(v237);  
      LOBYTE(v214) = (unsigned __int8)v214 >> v215;  
      v216 = __readeflags();  
      v237 = v216;  
    }  
    if ( v0->vm_instruction_opcode2 == (char)0xA3 )  
    {  
      __writeeflags(v237);  
      LOWORD(v214) = (unsigned __int16)v214 >> v215;  
      v217 = __readeflags();  
      v237 = v217;  
    }  
    if ( v0->vm_instruction_opcode2 == (char)0xA4 )  
    {  
      __writeeflags(v237);  
      v214 = (unsigned int)v214 >> v215;  
      v218 = __readeflags();  
      v237 = v218;  
    }  
    if ( v0->vm_instruction_opcode2 == (char)0xA5 )  
    {  
      __writeeflags(v237);  
      v214 >>= v215;  
      __readeflags();  
    }  
    vm_operation_result_selector_maybe = v0->vm_operation_result_selector_maybe;  
    if ( vm_operation_result_selector_maybe <= 0x8Eu )  
      v0->vm_left_value_1 = v214 ^ 0x2787FB21;  
    else  
      v0->vm_left_value_2 = v214 + 0x116ABA2E;  
  }  
```  
  
참고로 산술 연산이라면 오퍼레이션 직후 pushfq (__readeflags) 가 존재 할 가능성이 높다.  
  
```  
  // 간소화된 예시임. 실제와 다름.  
  // push operation  
  if ( vm_instruction_opcode1 == 0x6A )  
  {  
    if ( (_BYTE)p_vm_instruction_opcode5 == 2 )  
    {  
      LOWORD(v34) = v18;  
    }  
    else  
    {  
      LOWORD(v34) = HIWORD(v18);  
      v20 = ((_BYTE)v0 - 0x48) & (v18 + v20) ^ 0xF;  
    }  
  }  
    
  ...  
    
  // stack pointer adjust  
  v26 = (p_vm_instruction_opcode5 | 0x47) - 4;  
  v27 = v0->vm_instruction_opcode1 - 0x6A;  
  if ( v0->vm_instruction_opcode1 == 0x6A )  
  {  
    if ( v24 == 2 )  
    {  
      *(_QWORD *)vm_stack_pointer -= 2LL;  
    }  
    else  
    {  
      *(_QWORD *)vm_stack_pointer -= 8LL;  
      LOBYTE(v26) = v27 ^ (((v27 ^ v26) - 0xF) | 0x28);  
    }  
    v26 = (unsigned __int8)v26 & 0xA8;  
  }  
  LOBYTE(p_vm_instruction_opcode5) = v0->vm_instruction_opcode1;  
  v28 = p_vm_instruction_opcode5 | (v26 + 0x8000FBFFLL);  
  if ( (_BYTE)p_vm_instruction_opcode5 == 0x1C )  
  {  
    vm_opnd_maybe_1 = v0->vm_opnd_maybe_1;  
    v28 = 0x400 - vm_opnd_maybe_1;  
    if ( (char *)(vm_opnd_maybe_1 - 0x31AC9D7C) != vm_stack_pointer )  
    {  
      if ( v24 == 2 )  
        *(_QWORD *)vm_stack_pointer += 2LL;  
      else  
        *(_QWORD *)vm_stack_pointer += 8LL;  
      v28 = 0x3E4LL;  
    }  
  }  
```  
  
더미다는 핸들러에서 디스패쳐를 따로 거치치 않는다. 핸들러에서 바로 다음 핸들러로 이동한다.  
  
```  
  // 간소화된 예시임. 실제와 다름.  
  vmctx->vm_handlerKey -= 0x5AC92481;  
  vmctx->vm_handlerKey ^= 0x3F8BFC4F;  
  vmctx->vm_handlerKey ^= 0x2DDDE2;  
    
  v1 = *(unsigned __int16 *)(vmctx->vm_instruction_pointer + 4);  
  index = v1 - vmctx->vm_handlerKey;  
  vmctx->vm_handlerKey &= index;  
    
  next_handler = vmctx->vm_handlerTable[(unsigned __int16)index];  
    
  // VIP 업데이트  
  vmctx->vm_instruction_pointer += *(int *)vmctx->vm_instruction_pointer;  
    
  jump next_handler;  
```  
  
### VM EXIT:  
  
VM CONTEXT에 들어있던 레지스터들을 실제 레지스터로 전환한다. 그리고 스핀락을 해제한다.  
  
따라서 VM CONTEXT -> STACK -> REAL CONTEXT 전환 과정이 들어있다.  
  
 ```  
 // 간소화된 예시임. 실제와 다름.  
 .themida:14000AEA2  pop r8  
 .themida:14000AEA4  pop r9  
 .themida:14000AEA6  pop r10  
 .themida:14000AEA8  pop r11  
 .themida:14000AEAA  pop r12  
 .themida:14000AEAC  pop r13  
 .themida:14000AEAE  pop r14  
 .themida:14000AEB0  pop r15  
 .themida:14000AEB2  pop rdi  
 .themida:14000AEB3  pop rsi  
 .themida:14000AEB4  pop rbp  
 .themida:14000AEB5  pop rbx  
 .themida:14000AEB6  pop rdx  
 .themida:14000AEB7  pop rcx  
 .themida:14000AEB8  pop rax  
 .themida:14000AEB9  popfq  
 .themida:14000AEBA  popfq  
 .themida:14000AEBB  retn    0  
 ```  
  
---  
  
## 핸들러 동작 원리 및 특징  
  
1. **바이트코드에서 opcode fetch**  
   - `*(unsigned __int16*)(vm_bytecodePtr + offset)` 등으로 2바이트를 읽고, `vm_handlerKey`와 XOR/ADD 등 수행.  
   - 결과를 `& 0xffff` 후 × 8 → **handler table**에서 “다음 핸들러” 주소를 구한다.  
2. **VM CONTEXT 조작**  
   - 산술/논리 연산을 `vReg_RAX`, `vReg_RBX`, `vm_flagsA/B`, `field_0[...](스택)` 등에 적용.  
   - EFLAGS 대신 `vm_flagsA` 등으로 시뮬레이션하거나, 부분적으로 pushfq/popfq, __readeflags()/__writeeflags() 등을 써서 난독화.  
3. **옵코드**  
   - “if (vm_instruction_opcodeN == 0x16) then pop 2 bytes from field_0[...]” 식 로직이 흔함.  
   - opcode 상위/하위 4비트(`(value & 0xF0)>>4`, `(value & 0xF)`) 같은게 보였음. opcodeMain, subOpcode 같은 개념이 존재 할수도 있음  
4. **다음 바이트코드로 이동**  
   - `vm_bytecodePtr += *(int*)(vm_bytecodePtr + someOffset)`  
   - 핸들러마다 다른 offset이 있다. ex) +6, +3, +4, etc.  
  
------  
  
## 핸들러 코드 분석 예시  
  
아래는 일부 실제 핸들러(난독화된) 형태를 단순화한 예시:  
  
```c  
__int64 __fastcall sub_14003411C(VM_CONTEXT *v0) {  
  if ((v0->vm_handlerKey & 2) != 0)  
    v0->vm_flagsA += 0x7660110;  
  // swap(vm_handlerKey, vm_flagsA)  
  int tmp = v0->vm_handlerKey;  
  v0->vm_handlerKey = v0->vm_flagsA;  
  v0->vm_flagsA     = tmp;  
    
  // ... 각종 VM 명령어 실행 (오퍼랜드 fetch, 실행 등)  
    
  // bartecode fetch  
  unsigned int opcode = *(unsigned __int16*)v0->vm_bytecodePtr;  
  // next handler = handlerTable[opcode * 8]  
  __int64 nextHandler = *( (__int64*)(v0->vm_handlerTable + (opcode & 0xFFFF) * 8) );  
    
  // vm_bytecodePtr += *(int*)(v0->vm_bytecodePtr + 3)  
  v0->vm_bytecodePtr += *(int*)(v0->vm_bytecodePtr + 3);  
  
  // call/jmp nextHandler  
  return ((handlerFuncType)nextHandler)(...);  
}  
```  
  
이처럼 **핸들러**는 “(1) VM CONTEXT 업데이트 → (2) 바이트코드에서 opcode 추출 → (3) 다음 핸들러 주소 계산 → (4) 바이트코드 포인터 이동” 순으로 동작한다.  
  
---  
  
## 더미다 분석기 제작 아이디어  
  
1. 초기 분석 단계  
   - 바이너리를 로드하고 지정된 주소에서 가상화된 코드 실행 시작  
   - 모든 레지스터들을 심볼릭하게 설정하고 Triton 엔진으로 명령어 에뮬레이션  
   - vm context의 주요 오프셋 식별 (vip/vsp 레지스터 등)  
   - vip/vsp 레지스터를 심볼릭화하여 이후 메모리 접근 추적  
2. 핸들러 패턴 매칭  
   - 각 핸들러의 마지막 store 명령에서 저장되는 값의 AST 분석  
   - 패턴과 매칭하여 해당 핸들러의 연산 의미 파악  
   - 패턴 예시:  
     - "[vsp] + [vsp]" → ADD  
     - "~[vsp] | ~[vsp]" → NAND  
     - "[vsp] >> ([vsp] & 0x3f)" → SHR  
3. 제어 흐름 분석과 변환  
   - 식별된 핸들러를 basic block으로 변환  
   - RIP 레지스터를 슬라이싱하여 다음 basic block 주소 탐색  
   - Basic block들을 연결하여 제어 흐름 그래프 구성  
   - 모든 basic block을 LLVM IR로 변환하여 실행 가능한 코드로 복원  
4. 최적화 단계 (옵션)  
   - LLVM 최적화 패스 적용  
