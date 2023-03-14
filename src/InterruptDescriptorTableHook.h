#pragma once

void* hookInterruptServiceRoutine(unsigned long interruptIndex, void* hookFunction);

void* unhookInterruptServiceRoutine(unsigned long interruptIndex, void* originalInterruptServiceRoutine);