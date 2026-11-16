/**
 * The policy builder library of step 7.3 (design §4.7; ADR-0063): a catalogue-driven, lossless
 * editor model of `policy-dsl/1` documents, the readable summary, the version diff and the
 * builder components. Controlled components, no data fetching, no policy evaluation.
 */
export {
  CatalogShapeError,
  changeLeafField,
  changeLeafOperator,
  defaultLeaf,
  fieldsFor,
  fieldsForAll,
  operatorsFor,
  toBuilderCatalog,
  whenPlacesOf,
  type BuilderCatalog,
  type BuilderPlace,
  type CatalogAction,
  type CatalogActionParam,
  type CatalogField,
  type CatalogOperator,
} from './catalog';
export {
  buildDefinition,
  canonicalJson,
  canonicalPrettyJson,
  documentBytes,
  emptyDefinition,
  MODEL_DSL_VERSION,
  parseDefinition,
  type BuilderAction,
  type BuilderDefinition,
  type BuilderGroup,
  type BuilderLeaf,
  type BuilderNode,
  type BuilderNot,
  type BuilderRule,
  type ParseResult,
  type PolicyDirection,
  type PolicyDslDocument,
} from './model';
export {
  builderReducer,
  useBuilderState,
  type BuilderCommand,
  type BuilderLimits,
} from './reducer';
export { describePath, keyForPath, pathForKey, type PathIndex } from './paths';
export {
  summarizeDefinition,
  summaryToText,
  type DirectoryNames,
  type PolicySummaryDoc,
  type RuleSummary,
  type SummaryLine,
  type SummaryToken,
} from './summary';
export { diffDefinitions, lineDiff, type DefinitionDiff, type LineDiff } from './diff';
export {
  BuilderProvider,
  useBuilderContext,
  type BuilderDirectory,
  type DirectoryOption,
  type Violation,
} from './context';
export { PolicyBuilderEditor } from './editor';
export { PolicySummaryView } from './summary-view';
export { DefinitionDiffView, type DiffViewMode } from './diff-view';
export { ViolationList } from './violation-list';
export { SyntheticFactsForm } from './facts-form';
export { FACT_PRESETS, type PolicyTestResponse, type SyntheticFacts } from './facts';
export { EvaluationResultView } from './result-view';
