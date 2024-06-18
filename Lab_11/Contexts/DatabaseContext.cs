using Lab_11.DbModels;
using Microsoft.EntityFrameworkCore;

namespace Lab_11.Contexts;

public class DatabaseContext : DbContext
{
    public DbSet<User> Users { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }

    protected DatabaseContext()
    {
    }

    public DatabaseContext(DbContextOptions options) : base(options)
    {
    }
}