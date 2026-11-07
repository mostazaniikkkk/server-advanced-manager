package dev.sam.common.lua;

import java.time.Duration;

public record ScriptLimits(Duration perCall, long allocationBytes, int maxStringBytes) {
}
