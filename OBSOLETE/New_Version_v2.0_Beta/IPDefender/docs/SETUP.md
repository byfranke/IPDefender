# IPDefender Setup Instructions

## Prerequisites

Before you begin, ensure you have the following installed on your system:

- Python 3.7 or higher
- pip (Python package installer)
- Git
- Docker (optional, for containerized deployment)

## Installation Steps

1. **Clone the Repository**

   Open your terminal and run the following command to clone the repository:

   ```
   git clone https://github.com/yourusername/IPDefender.git
   cd IPDefender
   ```

2. **Create a Virtual Environment (Recommended)**

   It's a good practice to use a virtual environment to manage dependencies. You can create one using the following commands:

   ```
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies**

   Install the required packages using pip:

   ```
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**

   Create a `.env` file in the root directory of the project and add the necessary environment variables. You can use the `.env.example` file as a reference.

   ```
   cp .env.example .env
   ```

   Make sure to fill in the required values, such as your Cloudflare API token and zone ID.

5. **Database Setup**

   If your project uses a database, run the migration script to set up the database schema:

   ```
   python scripts/migrate.py
   ```

6. **Seed Initial Data (Optional)**

   If you want to seed the database with initial data, run:

   ```
   python scripts/seed_data.py
   ```

7. **Run the Application**

   You can start the application by running:

   ```
   python src/main.py
   ```

   If you are using Docker, you can build and run the containers with:

   ```
   docker-compose up --build
   ```

## Usage

After setting up the project, you can use the command line interface to block or unblock IPs. For example:

- To block an IP:

  ```
  python src/api/cloudflare.py add <IP_ADDRESS>
  ```

- To unblock an IP:

  ```
  python src/api/cloudflare.py delete <IP_ADDRESS>
  ```

## Contributing

If you would like to contribute to this project, please refer to the `CONTRIBUTING.md` file for guidelines.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.