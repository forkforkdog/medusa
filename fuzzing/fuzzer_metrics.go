package fuzzing

import (
	"math/big"
	"sync"

	"github.com/crytic/medusa/fuzzing/contracts"
)

// methodCallStats tracks call statistics for a single method
type methodCallStats struct {
	totalCalls   *big.Int
	successCalls *big.Int
}

// FuzzerMetrics represents a struct tracking metrics for a Fuzzer run.
type FuzzerMetrics struct {
	// workerMetrics describes the metrics for each individual worker. This expands as needed and some slots may be nil
	// while workers are initializing, as it corresponds to the indexes in Fuzzer.workers.
	workerMetrics []fuzzerWorkerMetrics

	// methodStats tracks per-method call statistics across all workers
	methodStats map[contracts.ContractMethodID]*methodCallStats
	// methodStatsLock protects concurrent access to methodStats
	methodStatsLock sync.Mutex
}

// fuzzerWorkerMetrics represents metrics for a single FuzzerWorker instance.
type fuzzerWorkerMetrics struct {
	// sequencesTested is the amount of sequences of transactions which tests were run against.
	sequencesTested *big.Int

	// failedSequences is the amount of sequences of transactions which tests failed.
	failedSequences *big.Int

	// callsTested is the amount of transactions/calls the fuzzer executed and ran tests against.
	callsTested *big.Int

	// gasUsed is the amount of gas the fuzzer executed and ran tests against.
	gasUsed *big.Int

	// workerStartupCount is the amount of times the worker was generated, or re-generated for this index.
	workerStartupCount *big.Int

	// shrinking indicates whether the fuzzer worker is currently shrinking.
	shrinking bool
}

// newFuzzerMetrics obtains a new FuzzerMetrics struct for a given number of workers specified by workerCount.
// Returns the new FuzzerMetrics object.
func newFuzzerMetrics(workerCount int) *FuzzerMetrics {
	// Create a new metrics struct and return it with as many slots as required.
	metrics := FuzzerMetrics{
		workerMetrics: make([]fuzzerWorkerMetrics, workerCount),
		methodStats:   make(map[contracts.ContractMethodID]*methodCallStats),
	}
	for i := 0; i < len(metrics.workerMetrics); i++ {
		metrics.workerMetrics[i].sequencesTested = big.NewInt(0)
		metrics.workerMetrics[i].failedSequences = big.NewInt(0)
		metrics.workerMetrics[i].callsTested = big.NewInt(0)
		metrics.workerMetrics[i].workerStartupCount = big.NewInt(0)
		metrics.workerMetrics[i].gasUsed = big.NewInt(0)
	}
	return &metrics
}

// FailedSequences returns the number of sequences that led to failures across all workers
func (m *FuzzerMetrics) FailedSequences() *big.Int {
	failedSequences := big.NewInt(0)
	for _, workerMetrics := range m.workerMetrics {
		failedSequences.Add(failedSequences, workerMetrics.failedSequences)
	}
	return failedSequences
}

// SequencesTested returns the amount of sequences of transactions the fuzzer executed and ran tests against.
func (m *FuzzerMetrics) SequencesTested() *big.Int {
	sequencesTested := big.NewInt(0)
	for _, workerMetrics := range m.workerMetrics {
		sequencesTested.Add(sequencesTested, workerMetrics.sequencesTested)
	}
	return sequencesTested
}

// CallsTested returns the amount of transactions/calls the fuzzer executed and ran tests against.
func (m *FuzzerMetrics) CallsTested() *big.Int {
	transactionsTested := big.NewInt(0)
	for _, workerMetrics := range m.workerMetrics {
		transactionsTested.Add(transactionsTested, workerMetrics.callsTested)
	}
	return transactionsTested
}

func (m *FuzzerMetrics) GasUsed() *big.Int {
	gasUsed := big.NewInt(0)
	for _, workerMetrics := range m.workerMetrics {
		gasUsed.Add(gasUsed, workerMetrics.gasUsed)
	}
	return gasUsed
}

// WorkerStartupCount describes the amount of times the worker was spawned for this index. Workers are periodically
// reset.
func (m *FuzzerMetrics) WorkerStartupCount() *big.Int {
	workerStartupCount := big.NewInt(0)
	for _, workerMetrics := range m.workerMetrics {
		workerStartupCount.Add(workerStartupCount, workerMetrics.workerStartupCount)
	}
	return workerStartupCount
}

// WorkersShrinkingCount returns the amount of workers currently performing shrinking operations.
func (m *FuzzerMetrics) WorkersShrinkingCount() uint64 {
	shrinkingCount := uint64(0)
	for _, workerMetrics := range m.workerMetrics {
		if workerMetrics.shrinking {
			shrinkingCount++
		}
	}
	return shrinkingCount
}

// RecordMethodCall records a call to a specific method with its success status.
// This is thread-safe and can be called from multiple workers concurrently.
func (m *FuzzerMetrics) RecordMethodCall(methodID contracts.ContractMethodID, success bool) {
	m.methodStatsLock.Lock()
	defer m.methodStatsLock.Unlock()

	// Initialize stats for this method if it doesn't exist
	if _, exists := m.methodStats[methodID]; !exists {
		m.methodStats[methodID] = &methodCallStats{
			totalCalls:   big.NewInt(0),
			successCalls: big.NewInt(0),
		}
	}

	// Increment total calls
	m.methodStats[methodID].totalCalls.Add(m.methodStats[methodID].totalCalls, big.NewInt(1))

	// Increment success calls if the call was successful
	if success {
		m.methodStats[methodID].successCalls.Add(m.methodStats[methodID].successCalls, big.NewInt(1))
	}
}

// GetMethodStats returns a copy of the method statistics map.
// Returns a map of method IDs to their total and successful call counts.
func (m *FuzzerMetrics) GetMethodStats() map[contracts.ContractMethodID]*methodCallStats {
	m.methodStatsLock.Lock()
	defer m.methodStatsLock.Unlock()

	// Create a deep copy to avoid concurrent access issues
	statsCopy := make(map[contracts.ContractMethodID]*methodCallStats)
	for methodID, stats := range m.methodStats {
		statsCopy[methodID] = &methodCallStats{
			totalCalls:   new(big.Int).Set(stats.totalCalls),
			successCalls: new(big.Int).Set(stats.successCalls),
		}
	}
	return statsCopy
}

// GetMethodCallCount returns the total number of calls for a specific method.
func (m *FuzzerMetrics) GetMethodCallCount(methodID contracts.ContractMethodID) *big.Int {
	m.methodStatsLock.Lock()
	defer m.methodStatsLock.Unlock()

	if stats, exists := m.methodStats[methodID]; exists {
		return new(big.Int).Set(stats.totalCalls)
	}
	return big.NewInt(0)
}

// GetMethodSuccessCount returns the number of successful calls for a specific method.
func (m *FuzzerMetrics) GetMethodSuccessCount(methodID contracts.ContractMethodID) *big.Int {
	m.methodStatsLock.Lock()
	defer m.methodStatsLock.Unlock()

	if stats, exists := m.methodStats[methodID]; exists {
		return new(big.Int).Set(stats.successCalls)
	}
	return big.NewInt(0)
}
