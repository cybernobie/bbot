/**
 * @name DOM-based XSS via jQuery :contains selector
 * @description Untrusted input like location.hash in a jQuery :contains selector can lead to XSS when jQuery processes the selector.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id js/dom-xss-jquery-contains-selector
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript
import DataFlow
import DataFlow::PathGraph

/**
 * Taint tracking configuration for location.hash being used unsafely in jQuery selectors.
 */
class HashToJQueryContainsConfig extends TaintTracking::Configuration {
  HashToJQueryContainsConfig() { this = "HashToJQueryContainsConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::PropRead hashProp |
      hashProp = source and
      hashProp.getPropertyName() = "hash" and
      exists(DataFlow::PropRead locationProp |
        locationProp = hashProp.getBase() and
        locationProp.getPropertyName() = "location"
      )
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode jqueryCall |
      (jqueryCall.getCalleeName() = "$" or jqueryCall.getCalleeName() = "jQuery") and
      sink = jqueryCall.getArgument(0) and
      (
        // String concatenation or template literals used in the selector
        sink.asExpr() instanceof BinaryExpr
        or sink.asExpr() instanceof AddExpr
        or exists(string val |
          val = sink.getStringValue() and
          val.indexOf(":contains(") >= 0
        )
      )
    )
  }
}

/**
 * Execute the taint tracking analysis.
 */
from HashToJQueryContainsConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "The value from $@ is used unsafely in a jQuery `:contains()` selector, potentially leading to DOM XSS.",
  source.getNode(), "location.hash"
