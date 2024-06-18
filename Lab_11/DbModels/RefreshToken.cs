using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Lab_11.DbModels;

[Table("Refresh_tokens")]
public class RefreshToken
{
    [Key]
    [Column("id")]
    public int Id { get; set; }

    [Column("token")]
    public string Token { get; set; } = null!;

    [Column("expiry_date")]
    public DateTime ExpiryDate { get; set; }

    [ForeignKey("Id")]
    [Column("User_id")]
    public int UserId { get; set; }

    public User User { get; set; } = null!;
}