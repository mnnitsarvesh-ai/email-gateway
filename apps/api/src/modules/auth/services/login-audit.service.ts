import { Injectable, Logger } from '@nestjs/common';
import { type LoginAuditEntry, LoginAuditRepository } from '../repositories/login-audit.repository';

/**
 * Writes the one `login_audit_logs` row of every login path (D6). A failed write is logged and
 * never changes the outcome the client sees (the generic answer must not depend on it).
 */
@Injectable()
export class LoginAuditService {
  private readonly logger = new Logger(LoginAuditService.name);

  constructor(private readonly repository: LoginAuditRepository) {}

  async record(entry: LoginAuditEntry): Promise<void> {
    try {
      await this.repository.insert(entry);
    } catch (err) {
      this.logger.error({
        message: 'Failed to write the login audit row',
        outcome: entry.outcome,
        err,
      });
    }
  }
}
