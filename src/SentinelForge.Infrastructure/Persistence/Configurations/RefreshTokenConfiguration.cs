using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelForge.Domain.Entities;

namespace SentinelForge.Infrastructure.Persistence.Configurations;

internal sealed class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("refresh_tokens");

        builder.HasKey(t => t.Id);
        builder.Property(t => t.Id).ValueGeneratedNever();
        builder.Property(t => t.TokenHash).HasMaxLength(RefreshToken.TokenHashLength).IsFixedLength().IsRequired();
        builder.Property(t => t.CreatedAt).HasColumnType("timestamp with time zone").IsRequired();
        builder.Property(t => t.ExpiresAt).HasColumnType("timestamp with time zone").IsRequired();
        builder.Property(t => t.UsedAt).HasColumnType("timestamp with time zone");
        builder.Property(t => t.RevokedAt).HasColumnType("timestamp with time zone");
        builder.Property(t => t.RevokedReason).HasMaxLength(RefreshToken.RevokedReasonMaxLength);
        builder.Property(t => t.CreatedByIp).HasMaxLength(AuditLog.IpAddressMaxLength);

        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(t => t.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasIndex(t => t.TokenHash).IsUnique().HasDatabaseName("ux_refresh_tokens_token_hash");
        builder.HasIndex(t => t.SessionId).HasDatabaseName("ix_refresh_tokens_session_id");
        builder.HasIndex(t => t.UserId).HasDatabaseName("ix_refresh_tokens_user_id");
    }
}
