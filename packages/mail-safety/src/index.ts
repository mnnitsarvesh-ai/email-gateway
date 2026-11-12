/**
 * `@email-gateway/mail-safety` (step 5.3 Q1, Q11, Q22; docs/plan/steps/17-quarantine.md;
 * ADR-0048, ADR-0049): the sanitized, DLP-masked quarantine preview (JSON text only, defanged
 * links), DLP masking of display text, signed/encrypted detection and the streaming WARN body
 * banner. Pure functions and streams: no I/O beyond the streams the caller passes, no clock
 * (time is a parameter), no logger.
 */
export {
  renderPreview,
  quarantinePreviewSchema,
  DEFAULT_PREVIEW_LIMITS,
  PREVIEW_VERSION,
  BODY_UNAVAILABLE_REASONS,
  type QuarantinePreview,
  type PreviewInput,
  type PreviewLimits,
  type PreviewAttachmentInput,
  type BodyUnavailableReason,
} from './preview';
export {
  htmlToPreviewText,
  DROPPED_ELEMENTS,
  type HtmlToTextResult,
  type HtmlToTextLimits,
} from './html-to-text';
export {
  maskDlp,
  dlpCandidates,
  MASK_CHAR,
  MASK_MAX_CHARS,
  type MaskDlpOptions,
  type MaskDlpResult,
} from './dlp-mask';
export { defangUrl, DEFANGED_URL_MAX_CHARS, type DefangedUrl } from './defang';
export { detectSignedOrEncrypted, SIGNATURE_HEAD_BYTES, type SignedOrEncrypted } from './signed';
export {
  insertWarningBanner,
  insertWarningBannerBuffer,
  bannerText,
  textBanner,
  htmlBanner,
  bodyInsertOffset,
  BANNER_LEVELS,
  BANNER_STATUSES,
  BANNER_TEMPLATES,
  BANNER_PART_SKIP_REASONS,
  type BannerLevel,
  type BannerStatus,
  type BannerOptions,
  type BannerLimits,
  type BannerResult,
  type BannerPartSkipReason,
} from './banner';
