#include <avr/io.h>
#include "InterruptDispatcher.h"

class DummyHandler {
public:
    static constexpr bool canHandleVectNum(unsigned int vectNum) {
        return vectNum == 1;
    }
    static void __vector() {
      asm volatile(
        "1:   nop       \n\t"
        "     nop       \n\t"
        "     rjmp 1b   \n\t"
        :
        :
        : "memory"
      );
      __builtin_unreachable();
    }
};

template class InterruptDispatcher<DummyHandler>;

int main() {
    return 0;
}
