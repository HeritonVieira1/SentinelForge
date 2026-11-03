using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Infrastructure.Persistence.Configurations;

internal sealed class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
{
    public void Configure(EntityTypeBuilder<AuditLog> builder)
    {
        builder.ToTable("audit_logs", t => t.HasCheckConstraint("ck_audit_logs_action", EnumCheck.In<AuditAction>("Action")));

        builder.HasKey(a => a.Id);
        builder.Property(a => a.Id).ValueGeneratedNever();
        builder.Property(a => a.Action).HasConversion<string>().HasMaxLength(EnumCheck.ColumnLength).IsRequired();
        builder.Property(a => a.EntityName).HasMaxLength(AuditLog.EntityNameMaxLength).IsRequired();
        builder.Property(a => a.EntityId).IsRequired();
        builder.Property(a => a.OldValues).HasColumnType("jsonb");
        builder.Property(a => a.NewValues).HasColumnType("jsonb");
        builder.Property(a => a.IpAddress).HasMaxLength(AuditLog.IpAddressMaxLength);
        builder.Property(a => a.CreatedAt).HasColumnType("timestamp with time zone").IsRequired();

        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(a => a.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasIndex(a => new { a.EntityName, a.EntityId }).HasDatabaseName("ix_audit_logs_entity");
        builder.HasIndex(a => a.UserId).HasDatabaseName("ix_audit_logs_user_id");
        builder.HasIndex(a => a.CreatedAt).HasDatabaseName("ix_audit_logs_created_at");
    }
}
