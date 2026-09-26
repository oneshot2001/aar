import { describe, expect, test } from "bun:test";
import { encode } from "jpeg-js";
import { measureJpeg, parseRoi, separation, statistics } from "./luminance";

function frame(pixel: (x: number) => readonly number[]) {
  const data = Buffer.alloc(16 * 8 * 4);
  for (let y = 0; y < 8; y++) for (let x = 0; x < 16; x++) data.set([...pixel(x), 255], (y * 16 + x) * 4);
  return encode({ data, width: 16, height: 8 }, 100).data;
}

describe("hedge luminance", () => {
  test("measures separate pixel ROIs at scale 1000", () => {
    const result = measureJpeg(frame((x) => x < 8 ? [20, 20, 20] : [180, 180, 180]), [0, 0, 8, 8], [8, 0, 8, 8]);
    expect(result.width).toBe(16);
    expect(result.height).toBe(8);
    expect(result.roi_mean_milli).toBe(20000);
    expect(result.control_mean_milli).toBe(180000);
  });
  test("weights color with BT.601 instead of averaging RGB", () => {
    const value = measureJpeg(frame(() => [255, 0, 0])).roi_mean_milli;
    expect(value).toBeGreaterThan(75000);
    expect(value).toBeLessThan(77000);
    expect(Number.isInteger(value)).toBe(true);
  });
  test("full frame defaults and 0/255 endpoints", () => {
    expect(measureJpeg(frame(() => [0, 0, 0])).roi_mean_milli).toBe(0);
    const white = measureJpeg(frame(() => [255, 255, 255]));
    expect(white.roi_mean_milli).toBe(255000);
    expect(white.roi).toEqual([0, 0, 16, 8]);
  });
  test("rejects malformed and out-of-bounds ROIs and unreadable JPEGs", () => {
    for (const value of ["-1,0,1,1", "0,0,0,1", "0,0,1.5,1", "0,0,1", "0,0,9007199254740992,1"]) {
      expect(() => parseRoi(value)).toThrow();
    }
    expect(() => measureJpeg(frame(() => [0, 0, 0]), [15, 0, 2, 8])).toThrow();
    expect(() => measureJpeg(new Uint8Array([1, 2, 3]))).toThrow();
  });
  test("population stddev and signed separation use a one-Y denominator floor", () => {
    const baseline = statistics([10000, 12000, 14000]);
    expect(baseline).toEqual({ mean_milli: 12000, stddev_milli: 1633 });
    expect(separation(baseline, statistics([16000, 18000, 20000]))).toBe(3674);
    expect(separation(statistics([20000]), statistics([120000]))).toBe(100000);
    expect(separation(statistics([20000]), statistics([10000]))).toBe(-10000);
    expect(separation(baseline, baseline)).toBe(0);
  });
});
