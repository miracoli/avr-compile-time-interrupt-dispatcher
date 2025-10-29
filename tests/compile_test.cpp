#include <avr/interrupt.h>
#include <avr/io.h>

#include "InterruptDispatcher.h"

int main();

ISR(BADISR_vect) {
  while (true) {  // Change to your needs
  }
}

extern "C" void __dtors_end();

extern "C" void reset(void) __attribute__((used, naked));

extern "C" void reset(void) {
  asm("clr r1");
  SREG = 0;
  SP = RAMEND;
  goto *&__dtors_end;
}

extern "C" void _exit();

extern "C" void jmp_main(void) __attribute__((used, naked, section(".init9")));

extern "C" void jmp_main(void) {
  main();
  goto *&_exit;
}

class DummyHandler {
 public:
  static constexpr bool canHandleVectNum(unsigned int vectNum) {
    return vectNum == 1;
  }
  __attribute__((noreturn)) static void __vector() {
    asm volatile(
        "1:   nop       \n\t"
        "     nop       \n\t"
        "     rjmp 1b   \n\t"
        :
        :
        : "memory");
    __builtin_unreachable();
  }
};

template class InterruptDispatcher<false, DummyHandler>;

int main() {
  return 0;
}
