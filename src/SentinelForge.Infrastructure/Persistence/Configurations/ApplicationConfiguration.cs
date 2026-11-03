using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelForge.Domain.Entities;
using DomainApplication = SentinelForge.Domain.Entities.Application;

namespace SentinelForge.Infrastructure.Persistence.Configurations;

internal sealed class ApplicationConfiguration : IEntityTypeConfiguration<DomainApplication>
{
    public void Configure(EntityTypeBuilder<DomainApplication> builder)
    {
        builder.ToTable("applications");

        builder.HasKey(a => a.Id);
        builder.Property(a => a.Id).ValueGeneratedNever();
        builder.Property(a => a.Name).HasMaxLength(DomainApplication.NameMaxLength).IsRequired();
        builder.Property(a => a.Description).HasMaxLength(DomainApplication.DescriptionMaxLength).IsRequired();
        builder.Property(a => a.RepositoryUrl).HasMaxLength(DomainApplication.RepositoryUrlMaxLength);
        builder.Property(a => a.IsActive).IsRequired();
        builder.Property(a => a.CreatedAt).HasColumnType("timestamp with time zone").IsRequired();
        builder.Property(a => a.UpdatedAt).HasColumnType("timestamp with time zone").IsRequired();

        builder.HasOne(a => a.Owner)
            .WithMany()
            .HasForeignKey(a => a.OwnerUserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasMany(a => a.Vulnerabilities)
            .WithOne(v => v.Application)
            .HasForeignKey(v => v.ApplicationId)
            .OnDelete(DeleteBehavior.Restrict);
        builder.Navigation(a => a.Vulnerabilities).UsePropertyAccessMode(PropertyAccessMode.Field);

        builder.HasIndex(a => a.OwnerUserId).HasDatabaseName("ix_applications_owner_user_id");
        builder.HasIndex(a => a.Name).HasDatabaseName("ix_applications_name");
    }
}
