#include <avr/io.h>
#include "InterruptDispatcher.h"

class DummyHandler {
public:
    static constexpr bool canHandleVectNum(unsigned int vectNum) {
        return vectNum == 1;
    }
    static void __vector() {}
};

template class InterruptDispatcher<DummyHandler>;

int main() {
    return 0;
}
