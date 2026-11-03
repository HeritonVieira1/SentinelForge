using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelForge.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AuthAndRbac : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_users_role",
                table: "users");

            migrationBuilder.DropCheckConstraint(
                name: "ck_audit_logs_action",
                table: "audit_logs");

            // Converte os papéis existentes para o novo vocabulário (os CHECKs antigos já foram removidos).
            migrationBuilder.Sql("UPDATE users SET \"Role\" = CASE \"Role\" WHEN 'Viewer' THEN 'Developer' WHEN 'Analyst' THEN 'SecurityAnalyst' WHEN 'Admin' THEN 'Administrator' ELSE \"Role\" END;");

            migrationBuilder.AddColumn<int>(
                name: "FailedLoginCount",
                table: "users",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "LockoutEnd",
                table: "users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "refresh_tokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    SessionId = table.Column<Guid>(type: "uuid", nullable: false),
                    TokenHash = table.Column<string>(type: "character(64)", fixedLength: true, maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RevokedReason = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    CreatedByIp = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_refresh_tokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_refresh_tokens_users_UserId",
                        column: x => x.UserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.AddCheckConstraint(
                name: "ck_users_role",
                table: "users",
                sql: "\"Role\" IN ('Developer', 'SecurityAnalyst', 'Administrator')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_audit_logs_action",
                table: "audit_logs",
                sql: "\"Action\" IN ('Created', 'Updated', 'LoginSucceeded', 'LoginFailed', 'LoggedOut', 'RefreshTokenReuseDetected', 'SessionsRevoked')");

            migrationBuilder.CreateIndex(
                name: "ix_refresh_tokens_session_id",
                table: "refresh_tokens",
                column: "SessionId");

            migrationBuilder.CreateIndex(
                name: "ix_refresh_tokens_user_id",
                table: "refresh_tokens",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "ux_refresh_tokens_token_hash",
                table: "refresh_tokens",
                column: "TokenHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "refresh_tokens");

            migrationBuilder.DropCheckConstraint(
                name: "ck_users_role",
                table: "users");

            migrationBuilder.DropCheckConstraint(
                name: "ck_audit_logs_action",
                table: "audit_logs");

            migrationBuilder.DropColumn(
                name: "FailedLoginCount",
                table: "users");

            migrationBuilder.DropColumn(
                name: "LockoutEnd",
                table: "users");

            migrationBuilder.Sql("UPDATE users SET \"Role\" = CASE \"Role\" WHEN 'Developer' THEN 'Viewer' WHEN 'SecurityAnalyst' THEN 'Analyst' WHEN 'Administrator' THEN 'Admin' ELSE \"Role\" END;");
            migrationBuilder.Sql("DELETE FROM audit_logs WHERE \"Action\" NOT IN ('Created', 'Updated');");

            migrationBuilder.AddCheckConstraint(
                name: "ck_users_role",
                table: "users",
                sql: "\"Role\" IN ('Viewer', 'Analyst', 'Admin')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_audit_logs_action",
                table: "audit_logs",
                sql: "\"Action\" IN ('Created', 'Updated')");
        }
    }
}


