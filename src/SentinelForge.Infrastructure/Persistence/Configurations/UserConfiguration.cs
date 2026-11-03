using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Infrastructure.Persistence.Configurations;

internal sealed class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("users", t => t.HasCheckConstraint("ck_users_role", EnumCheck.In<UserRole>("Role")));

        builder.HasKey(u => u.Id);
        builder.Property(u => u.Id).ValueGeneratedNever();
        builder.Property(u => u.Name).HasMaxLength(User.NameMaxLength).IsRequired();
        builder.Property(u => u.Email).HasMaxLength(User.EmailMaxLength).IsRequired();
        builder.Property(u => u.PasswordHash).HasMaxLength(User.PasswordHashMaxLength).IsRequired();
        builder.Property(u => u.Role).HasConversion<string>().HasMaxLength(EnumCheck.ColumnLength).IsRequired();
        builder.Property(u => u.IsActive).IsRequired();
        builder.Property(u => u.CreatedAt).HasColumnType("timestamp with time zone").IsRequired();
        builder.Property(u => u.UpdatedAt).HasColumnType("timestamp with time zone").IsRequired();

        builder.HasIndex(u => u.Email).IsUnique().HasDatabaseName("ux_users_email");
    }
}
