#ifndef INTERRUPTDISPATCHER_H_
#define INTERRUPTDISPATCHER_H_

typedef void (*InterruptVectFuncPtr)();  // Define a function pointer type for interrupt vectors

// Declare existing external interrupt vector functions
extern "C" void __vector_default(void);
extern "C" void reset(void);

// Concept to verify if a type is a valid InterruptHandler
template<typename T>
concept InterruptHandler = requires(T t, unsigned int vectNum) {
  { T::canHandleVectNum(vectNum) } ;  // Ensures the handler has a static function to check if it can handle the vector number
  { T::__vector() } ;                 // Ensures the handler provides a static interrupt vector function
};

// Function to place the vector table into the vectors section
template<InterruptHandler... InterruptHandlers>
class InterruptDispatcher {
 private:
  static constexpr unsigned int VECTORS_NUM  = _VECTORS_SIZE / _VECTOR_SIZE; // total number of interrupts including the reset vector 
  #ifdef _AVR_AVR128DA28_H_INCLUDED
  static_assert(VECTORS_NUM == 41); // AVR128DA28 has 41 vectors (from number 0 to 40) starting with reset vector
  #endif

  InterruptDispatcher() = delete; // Prevent instantiation of this class

  // Declare the vectors function as naked (no prologue/epilogue)
  // This is the entry point for the interrupt vector table
  static __attribute__((section(".vectors"))) void vectors(void) __attribute__((naked)) {
    generateVectorTable(); // Generate the vector table starting from the reset vector
  }

  // Dispatch function to find the correct interrupt handler for the given vector number
  template<InterruptHandler CurrentHandler, InterruptHandler ... RemainingHandlers>
  static consteval InterruptVectFuncPtr dispatch(unsigned int vectNum) {
    if (vectNum == 0) {
      return reset; // If the vectNum is 0 return the reset vector 
    }
    // Check if the current handler can handle the interrupt
    if (CurrentHandler::canHandleVectNum(vectNum)) {
      return CurrentHandler::__vector; // If it can, return the corresponding vector
    }
    // If the current handler can't handle it, recurse to check the remaining handlers
    if constexpr (sizeof...(RemainingHandlers) > 0) {
      return dispatch<RemainingHandlers...>(vectNum);
    }
    // If no handlers can handle the interrupt, return the default vector
    return __vector_default; 
  }

  // Template function to generate the vector table
  template<int VECT_NUM = 0>
  static __attribute__((always_inline)) inline void generateVectorTable() {
    // Inline assembly to jump to the dispatch function for the current vector
    asm volatile("jmp %x0 \n\t" : : "p"(dispatch<InterruptHandlers...>(VECT_NUM)));
    // Recursively generate the table for the next vector if within bounds
    if constexpr (VECT_NUM + 1 < VECTORS_NUM) {
      generateVectorTable<VECT_NUM + 1>(); 
    }
  }
};

#endif /* INTERRUPTDISPATCHER_H_ */
