# AVR Compile-Time Interrupt Dispatcher

A header-only library designed for **compile-time interrupt dispatching** on AVR microcontrollers. This library leverages C++ metaprogramming to efficiently generate an interrupt vector table at compile time, ensuring zero runtime overhead and enabling type-safe interrupt handler selection.

## How It Works

The library uses C++ templates and concepts to define interrupt handlers and generate the corresponding interrupt vector table. At compile time, it ensures that handlers are compatible with specific interrupt vector numbers, eliminating the need for runtime checks.

The vector table is placed in the `.vectors` section of memory and is automatically populated with the correct handler addresses, including a default handler for unhandled interrupts.

## Example Usage

To use the library, define interrupt handlers using a class with two static members:
1. `canHandleVectNum`: A method to determine if the handler can handle a specific vector number.
2. `__vector`: The actual interrupt service routine (ISR) for the handler.

```cpp
#include "InterruptDispatcher.h"

// Example Interrupt Handler
class TimerHandler {
public:
  // This handler can handle interrupt vector 1
  static constexpr bool canHandleVectNum(unsigned int vectNum) {
    return vectNum == 1;
  }

  // ISR for Timer Interrupt
  static void __vector() {
    // Timer interrupt service routine code
  }
};

// Example usage of InterruptDispatcher
template class InterruptDispatcher<TimerHandler>;
```

### How to Add More Handlers
You can define multiple interrupt handlers by adding more classes and passing them to `InterruptDispatcher`:

```cpp
class UARTHandler {
public:
  static constexpr bool canHandleVectNum(unsigned int vectNum) {
    return vectNum == 2; // Handles UART interrupt (vector 2)
  }

  static void __vector() {
    // UART interrupt service routine code
  }
};

// Combine multiple handlers
template class InterruptDispatcher<TimerHandler, UARTHandler>;
```

## Requirements

- AVR microcontroller (e.g., AVR128DA28)
- AVR GCC toolchain for compiling your code.

## Installation

Simply download or clone the repository and include the `InterruptDispatcher.h` file in your project.

```bash
git clone https://github.com/miracoli/avr-compile-time-interrupt-dispatcher.git
```
Define your interrupt handler(s) (see above). Make sure to disable the usage of standard start files and add your own startup code.
An example for the AVR128DA28 looks like this:

```cpp
#include "InterruptDispatcher.h"

template class InterruptDispatcher<YOUR_INTERRUPT_HANDLER>;

ISR(BADISR_vect) {
  while (1) { // Change to your needs
  }
}

extern "C" void __dtors_end();

void reset(void) __attribute__((used, naked));

void reset(void) {
  asm("clr r1");
  SREG = 0;
  SP = RAMEND;
  goto *&__dtors_end;
}

extern "C" void _exit();

void jmp_main(void) __attribute__((used, naked, section(".init9")));

void jmp_main(void) {
  main();
  goto *&_exit;
}

```

## Contributing

Contributions are welcome! If you have suggestions or improvements, feel free to open an issue or submit a pull request.

See the [CONTRIBUTING.md](CONTRIBUTING.md) file for more details.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more details.

## Contact

For any questions or issues, feel free to reach out through GitHub Issues or contact me.

---

*Happy coding!*
