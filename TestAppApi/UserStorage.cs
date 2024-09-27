using TestApp.Contracts.Models;

namespace TestAppApi;

public static class UserStorage
{
    public static List<User> Users =>
    [
        new User
        {
            UserId = 1,
            Username = "admin",
            Password = "12Tester34#"
        }   
    ];
}
