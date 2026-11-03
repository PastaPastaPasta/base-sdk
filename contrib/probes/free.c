// SPDX-License-Identifier: CC0-1.0

int add(int a, int b)
{
  int sum = 0;
  return __builtin_add_overflow(a, b, &sum) ? 0 : sum;
}
