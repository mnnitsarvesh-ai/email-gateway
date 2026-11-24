import { Injectable } from '@nestjs/common';
import {
  isNativeTool,
  type OperationTool,
  REPORT_GENERATE,
  REPORT_SEND_EMAIL,
} from '@email-gateway/assistant';
import type { Prisma } from '@email-gateway/database';
import {
  type DeliveryActor,
  type DeliveryExecuteOptions,
  type DeliveryExecution,
  type DeliveryProposal,
  type DeliveryState,
  ReportDeliveryService,
} from './reports/report-delivery.service';
import {
  type GeneratedReport,
  type ReportGenerateInput,
  type ReportGenerateResult,
  ReportGeneratorService,
} from './reports/report-generator.service';
import type { ExecutionContext } from './tool-executor.service';

/**
 * The native tools of the assistant (step AI-R D1, D2, D5; ADR-0095): registry records that are
 * not OpenAPI operations, executed by the api's own services instead of the loopback. The
 * executor, proposer and confirm route call this dispatcher by tool name after their usual
 * steps (budget, lookup, availability and permission, refs, schema):
 *
 * - `report_generate` (read): `ReportGeneratorService` (fixed loopback reads of existing report
 *   operations with the user's own credential, the package renderer, object storage);
 * - `report_send_email` (write): `ReportDeliveryService` (the proposal with the recipient rule
 *   and limits, the confirm-time state, the confirmed delivery + outbox event).
 *
 * An unknown native name fails closed (`denied_disabled` / an error).
 */
@Injectable()
export class NativeToolsService {
  constructor(
    private readonly generator: ReportGeneratorService,
    private readonly delivery: ReportDeliveryService,
  ) {}

  isNative(tool: OperationTool): boolean {
    return isNativeTool(tool);
  }

  /** A native read (`report_generate`). */
  read(tool: OperationTool, input: ReportGenerateInput): Promise<ReportGenerateResult> {
    if (tool.name === REPORT_GENERATE.name) return this.generator.generate(input);
    return Promise.resolve({
      kind: 'denied',
      decision: 'denied_disabled',
      message: 'This tool is not enabled for chat yet; use the portal page.',
    });
  }

  /** The persist-transaction half of a native read (the report row and its audit). */
  finalizeRead(
    ctx: ExecutionContext,
    generated: GeneratedReport,
    executionRowId: bigint,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    return this.generator.finalize(ctx, generated, executionRowId, tx);
  }

  /** A native write's proposal (instead of the precondition read). */
  prepareProposal(
    tool: OperationTool,
    actor: DeliveryActor,
    args: Readonly<Record<string, unknown>>,
  ): Promise<DeliveryProposal> {
    if (tool.name === REPORT_SEND_EMAIL.name) {
      return this.delivery.prepareProposal(actor, tool, args);
    }
    return Promise.resolve({
      kind: 'denied',
      decision: 'denied_disabled',
      message: 'This tool is not enabled for chat yet; use the portal page.',
    });
  }

  /** A native write's confirm-time state (instead of the precondition re-read). */
  readState(
    tool: OperationTool,
    actor: DeliveryActor,
    args: Readonly<Record<string, unknown>>,
  ): Promise<DeliveryState> {
    if (tool.name === REPORT_SEND_EMAIL.name) return this.delivery.readState(actor, args);
    return Promise.resolve({ kind: 'refused' });
  }

  /** A confirmed native write, inside the execution's persist transaction. */
  execute(
    tool: OperationTool,
    actor: DeliveryActor & { clientIp: string | null },
    args: Readonly<Record<string, unknown>>,
    options: DeliveryExecuteOptions,
    tx: Prisma.TransactionClient,
  ): Promise<DeliveryExecution> {
    if (tool.name === REPORT_SEND_EMAIL.name) {
      return this.delivery.execute(actor, args, options, tx);
    }
    return Promise.resolve({
      kind: 'failed',
      status: 'failed',
      httpStatus: 501,
      recordedStatus: 501,
      code: 'tool_unavailable',
      message: 'This tool cannot run.',
    });
  }
}
