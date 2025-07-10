

import { expect, test } from "vitest";
import { harmonicMean, isPrefix, mean, skipWhile, takeWhile } from "../misc";

test("should return true if the first array is a prefix of the second array", () => {
  expect(isPrefix([1, 2], [1, 2, 3])).toBe(true);
  expect(isPrefix([], [1, 2, 3])).toBe(true);
  expect(isPrefix([0, 0], [1, 0])).toBe(false);
  expect(isPrefix([1, 2], [1, 2])).toBe(true);
});

test("should take elements while condition is true", () => {
  const arr = [1, 2, 3, 4, 5];
  const result = Array.from(takeWhile(arr, (x) => x < 4));
  expect(result).toEqual([1, 2, 3]);
});

test("should take no elements when condition is never true", () => {
  const arr = [1, 2, 3];
  const result = Array.from(takeWhile(arr, (x) => x < 0));
  expect(result).toEqual([]);
});

test("should take all elements when condition is always true", () => {
  const arr = [1, 2, 3];
  const result = Array.from(takeWhile(arr, (x) => x > 0));
  expect(result).toEqual([1, 2, 3]);
});

test("should skip elements while condition is true", () => {
  const arr = [1, 2, 3, 4, 5];
  const result = Array.from(skipWhile(arr, (x) => x < 4));
  expect(result).toEqual([4, 5]);
});

test("should skip no elements when condition is never true", () => {
  const arr = [1, 2, 3];
  const result = Array.from(skipWhile(arr, (x) => x < 0));
  expect(result).toEqual([1, 2, 3]);
});

test("should skip all elements when condition is always true", () => {
  const arr = [1, 2, 3];
  const result = Array.from(skipWhile(arr, (x) => x > 0));
  expect(result).toEqual([]);
});

test("should calculate mean correctly", () => {
  expect(mean([1, 2, 3, 4])).toBe(2.5);
  expect(mean([10, 20, 30])).toBe(20);
  expect(mean([-1, -2, -3])).toBe(-2);
});

test("should calculate harmonic mean correctly", () => {
  expect(harmonicMean([1, 2, 4])).toBeCloseTo(1.7142857142857142);
  expect(harmonicMean([2, 4, 8])).toBeCloseTo(3.4285714285714284);
  expect(harmonicMean([10, 20])).toBeCloseTo(13.333333333333334);
});

