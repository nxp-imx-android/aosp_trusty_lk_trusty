/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#pragma once

/**
 * enum bench_aggregate_idx - The position of the calculated aggregate in the
 * aggregate array of the bench_metric_node
 * @BENCH_AGGREGATE_MIN: index of the current minimum value for this metric.
 * @BENCH_AGGREGATE_MAX: index of the current maximum value for this metric.
 * @BENCH_AGGREGATE_AVG: index of the current average value for this metric.
 * @BENCH_NUM_AGGREGATE: Number of available aggregates. Indicates the end of
 * the enum possible values.
 */
enum bench_aggregate_idx {
    BENCH_AGGREGATE_MIN = 0,
    BENCH_AGGREGATE_MAX = 1,
    BENCH_AGGREGATE_AVG = 2,
    BENCH_NUM_AGGREGATE = 3
};

/**
 * struct bench_metric_node - holds current aggregate for the metrics of the
 * current bench.
 * @cnt:                Number of BENCH runs already aggregated.
 * @tot:                Total of all values returned by BENCH_RESULT.
 * @aggregates:         Array of computed aggregates.
 *                      BENCH_AGGREGATE_MIN: Smallest value returned by
 * BENCH_RESULT. BENCH_AGGREGATE_MAX: Highest value returned by BENCH_RESULT.
 *                      BENCH_AGGREGATE_AVG: Average value returned by
 * BENCH_RESULT.
 */
struct bench_metric_node {
    size_t cnt;
    int64_t tot;
    int64_t aggregates[BENCH_NUM_AGGREGATE];
};

/**
 * struct bench_metric_list_node - holds a metric declared by BENCH_RESULT in
 * a lk_list node
 * @node:               List node.
 * @metric:             Metric values container.
 * @name:               Name to use in summary table header for this metric.
 * @param_idx:          index of current param in param array this metric node
 *                      is aggregating for.
 * @col_sz:             size in bytes needed to print this column.
 * @bench_result:       Function pointer holding the BENCH_RESULT body
 *                      Used to get the value to be aggregate for this metric
 *                      after each BENCH body run.
 */
struct bench_metric_list_node {
    struct list_node node;
    struct bench_metric_node metric;
    const char* name;
    size_t param_idx;
    size_t col_sz;
    int64_t (*bench_result)(void);
};
