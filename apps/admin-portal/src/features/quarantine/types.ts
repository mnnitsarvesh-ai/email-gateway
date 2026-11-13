import type { ListItem, SuccessBody } from '@/lib/api/types';

export type EntrySummary = ListItem<'QuarantineEntriesController_search_v1'>;
export type EntryDetailBody = SuccessBody<'QuarantineEntriesController_detail_v1'>;
export type SelfEntryDetailBody = SuccessBody<'QuarantineSelfController_detail_v1'>;
export type PreviewBody = SuccessBody<'QuarantineEntriesController_preview_v1'>;
export type ReleaseView = SuccessBody<'QuarantineToolsController_release_v1'>;
export type ReleaseSummary = EntryDetailBody['releases'][number];
export type HistoryBody = SuccessBody<'QuarantineEntriesController_history_v1'>;
export type Approval = ListItem<'QuarantineApprovalsController_list_v1'>;
export type Catalog = SuccessBody<'QuarantineToolsController_catalog_v1'>;
export type SettingsBody = SuccessBody<'QuarantineToolsController_getSettings_v1'>;
export type ReleaseOutcome = SuccessBody<'QuarantineEntriesController_release_v1'>;
export type EntryAction = EntryDetailBody['allowedActions'][number];
export type BulkAction = Catalog['bulkActions'][number];
export type BulkResult = SuccessBody<'QuarantineToolsController_bulk_v1'>;
