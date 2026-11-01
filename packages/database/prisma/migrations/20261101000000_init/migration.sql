-- CreateTable
CREATE TABLE `tenants` (
    `id` CHAR(36) NOT NULL,
    `slug` VARCHAR(63) NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `status` ENUM('active', 'suspended', 'deleted') NOT NULL DEFAULT 'active',
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `tenants_slug_key`(`slug`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `tenant_domains` (
    `id` CHAR(36) NOT NULL,
    `tenant_id` CHAR(36) NOT NULL,
    `domain` VARCHAR(253) NOT NULL,
    `verification_status` ENUM('pending', 'verified', 'failed') NOT NULL DEFAULT 'pending',
    `verification_token` VARCHAR(64) NOT NULL,
    `verified_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `tenant_domains_domain_key`(`domain`),
    INDEX `tenant_domains_tenant_id_verification_status_idx`(`tenant_id`, `verification_status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `users` (
    `id` CHAR(36) NOT NULL,
    `tenant_id` CHAR(36) NOT NULL,
    `email` VARCHAR(320) NOT NULL,
    `display_name` VARCHAR(255) NOT NULL,
    `role` ENUM('tenant_admin', 'security_analyst', 'helpdesk', 'end_user') NOT NULL,
    `status` ENUM('invited', 'active', 'disabled') NOT NULL DEFAULT 'invited',
    `last_login_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `users_tenant_id_email_key`(`tenant_id`, `email`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `audit_logs` (
    `id` BIGINT NOT NULL AUTO_INCREMENT,
    `tenant_id` CHAR(36) NULL,
    `actor_type` ENUM('user', 'system', 'api_key') NOT NULL,
    `actor_id` VARCHAR(64) NULL,
    `action` VARCHAR(100) NOT NULL,
    `resource_type` VARCHAR(64) NOT NULL,
    `resource_id` VARCHAR(64) NULL,
    `correlation_id` VARCHAR(128) NULL,
    `source_ip` VARCHAR(45) NULL,
    `metadata` JSON NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `audit_logs_tenant_id_created_at_idx`(`tenant_id`, `created_at`),
    INDEX `audit_logs_resource_type_resource_id_idx`(`resource_type`, `resource_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `outbox_events` (
    `id` BIGINT NOT NULL AUTO_INCREMENT,
    `event_id` CHAR(36) NOT NULL,
    `tenant_id` CHAR(36) NOT NULL,
    `event_type` VARCHAR(100) NOT NULL,
    `correlation_id` VARCHAR(128) NOT NULL,
    `payload` JSON NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `published_at` DATETIME(3) NULL,
    `attempts` INTEGER UNSIGNED NOT NULL DEFAULT 0,

    UNIQUE INDEX `outbox_events_event_id_key`(`event_id`),
    INDEX `outbox_events_published_at_id_idx`(`published_at`, `id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `processed_events` (
    `consumer` VARCHAR(100) NOT NULL,
    `event_id` CHAR(36) NOT NULL,
    `processed_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `processed_events_processed_at_idx`(`processed_at`),
    PRIMARY KEY (`consumer`, `event_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `tenant_domains` ADD CONSTRAINT `tenant_domains_tenant_id_fkey` FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `users` ADD CONSTRAINT `users_tenant_id_fkey` FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

