import { decode } from "jpeg-js";

/** Pixel coordinates, with an exclusive right/bottom edge. Omission means full frame. */
export type Roi = readonly [x: number, y: number, width: number, height: number];

export function parseRoi(value: string): Roi {
  if (!/^\d+,\d+,\d+,\d+$/.test(value)) throw new Error("ROI must be x,y,w,h in integer pixels");
  const roi = value.split(",").map(Number) as unknown as Roi;
  validateRoi(roi);
  return roi;
}

function validateRoi(roi: Roi): void {
  if (roi.length !== 4 || !roi.every(Number.isSafeInteger) || roi[0] < 0 || roi[1] < 0 || roi[2] < 1 || roi[3] < 1) {
    throw new Error("ROI requires nonnegative x,y and positive w,h");
  }
}

export function measureJpeg(bytes: Uint8Array, roi?: Roi, controlRoi?: Roi) {
  const frame = decode(bytes, { useTArray: true, formatAsRGBA: true, tolerantDecoding: false,
    maxResolutionInMP: 40, maxMemoryUsageInMB: 256 });
  const full: Roi = [0, 0, frame.width, frame.height];
  const mean = (area: Roi): number => {
    validateRoi(area);
    const [x, y, w, h] = area;
    if (x + w > frame.width || y + h > frame.height) throw new Error("ROI is outside snapshot dimensions");
    let sum = 0;
    for (let row = y; row < y + h; row++) {
      for (let col = x; col < x + w; col++) {
        const i = (row * frame.width + col) * 4;
        // BT.601 full-range Y, accumulated at scale 1000 before rounding the mean.
        sum += 299 * frame.data[i]! + 587 * frame.data[i + 1]! + 114 * frame.data[i + 2]!;
      }
    }
    return Math.round(sum / (w * h));
  };
  return { width: frame.width, height: frame.height, roi: roi ?? full, control_roi: controlRoi ?? full,
    roi_mean_milli: mean(roi ?? full), control_mean_milli: mean(controlRoi ?? full) };
}

/** Population standard deviation across frame means; all output is Y * 1000. */
export function statistics(values: readonly number[]) {
  if (!values.length || !values.every((value) => Number.isSafeInteger(value) && value >= 0 && value <= 255000)) {
    throw new Error("statistics requires fixed-point frame means");
  }
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length;
  return { mean_milli: Math.round(mean), stddev_milli: Math.round(Math.sqrt(variance)) };
}

/** (post - baseline) / max(baseline population stddev, 1 Y), scaled by 1000. */
export function separation(baseline: ReturnType<typeof statistics>, post: ReturnType<typeof statistics>): number {
  return Math.round((post.mean_milli - baseline.mean_milli) * 1000 / Math.max(baseline.stddev_milli, 1000));
}
