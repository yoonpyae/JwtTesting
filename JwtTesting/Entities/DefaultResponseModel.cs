namespace dotNetProject.Models
{
    public class DefaultResponseModel
    {
        public bool Success { get; set; }
        public int StatusCode { get; set; }
        public string? Message { get; set; }
        public dynamic? Data { get; set; }
    }
}
