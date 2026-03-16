# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project and restore
COPY CandyCli/*.csproj ./CandyCli/
RUN dotnet restore CandyCli/CandyCli.csproj

# Copy rest and publish
COPY . .
RUN dotnet publish CandyCli/CandyCli.csproj -c Release -o /app/publish /p:TrimUnusedDependencies=true

# Runtime stage
FROM mcr.microsoft.com/dotnet/runtime:8.0
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "CandyCli.dll"]