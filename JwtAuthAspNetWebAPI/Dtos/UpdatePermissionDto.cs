using System.ComponentModel.DataAnnotations;

namespace JwtAuthAspNetWebAPI.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "User name is required")]
        public string UserName { get; set; }
    }
}
