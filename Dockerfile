# Skype.Server — .NET 8, для Render / Fly.io / любого Docker-хоста
# Корень сборки: папка server/Skype.Server (в Render: Root Directory = server/Skype.Server)

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY Skype.Server.csproj .
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .
# Порт задаёт Render через переменную PORT; локально: docker run -e PORT=8080 -p 8080:8080 ...
EXPOSE 8080
ENTRYPOINT ["dotnet", "Skype.Server.dll"]
