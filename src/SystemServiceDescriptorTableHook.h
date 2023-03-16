#pragma once

void hookNtFunction(void* zwFunction, void* hookFunction);

void unhookNtFunction(void* zwFunction);
