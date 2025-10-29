#include "compile_test_common.h"

template class InterruptDispatcher<true, DummyHandler>;

int main() {
  return 0;
}
