# NexBank - Modern Banking Application

Welcome to **NexBank**, a cutting-edge web-based banking application designed to provide secure, efficient, and user-friendly account management and transaction services. This project showcases a robust banking system built with a focus on security, real-time updates, and an engaging user interface.

## Project Overview

NexBank aims to revolutionize online banking by offering features like account registration, secure login with OTP verification, password recovery, fund transfers with fraud detection, transaction history tracking, and email-based statement generation. The project combines modern design with practical functionality, making it an ideal showcase for banking software development skills.

* **Mission**: To create a secure, scalable, and accessible banking platform that leverages advanced technologies to enhance user experience and transaction safety.
* **Vision**: To provide a foundation for future enhancements, such as mobile banking and advanced analytics, while maintaining high standards of security and performance.

## Technologies and Tools Used

* **Programming Language**: Java (core logic with JDBC for database connectivity)
* **Frontend Framework**: Streamlit (Python-based for interactive web interface)
* **Database**: MySQL (for storing account details, transactions, and user data)
* **HTTP Library**: `requests` (for API communication)
* **Data Manipulation**: `pandas` (for structuring transaction data)
* **Development Tools**: IntelliJ IDEA or VS Code (code editing and debugging)
* **Backend API**: Deployed at `https://state-bank-of-india.onrender.com` (likely built with Spring Boot or similar)
* **Styling**: Custom CSS with glassmorphism, animated gradients, and particle effects

## Features

* **Account Registration**: Sign up with an account number and email, verified via OTP.
* **Secure Login**: Authentication with password and OTP for enhanced security.
* **Password Recovery**: Multi-step process using security questions and OTP.
* **Fund Transfers**: Transfer funds with OTP confirmation and fraud detection.
* **Transaction History**: Real-time view of transactions in a styled table.
* **Statement Generation**: Email-based account statements for selected months and years.
* **User Interface**: Futuristic design with animated effects and responsive layout.

## How It Works

1. **Setup**: The application connects to a MySQL database via JDBC, fetching and storing data such as account balances and transaction logs.
2. **User Interaction**: The Streamlit interface provides a dashboard where users can navigate between registration, login, transfer, history, and statement features.
3. **Security**: OTP verification and rate limiting protect against unauthorized access, while fraud detection flags suspicious transactions.
4. **Data Flow**: API calls to the backend (e.g., `/get-transaction-history`, `/transfer`) handle requests, returning data in JSON or string format, which the frontend processes for display.
5. **Deployment**: The backend is hosted on Render, ensuring live accessibility, while the frontend runs locally or can be deployed similarly.

## Installation and Usage

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/your-username/nexbank.git
   cd nexbank
   ```

2. **Prerequisites**:

   * Install Java (JDK 11+)
   * Install Python (3.8+)
   * Install MySQL and configure a database
   * Install required Python packages:

     ```bash
     pip install streamlit pandas requests
     ```

3. **Configure Environment**:

   * Set up JDBC driver and database credentials.
   * Update the `BACKEND_URL` in the code to match the deployed API endpoint.

4. **Run the Application**:

   ```bash
   streamlit run app.py
   ```

   Open your browser at `http://localhost:8501` to access NexBank.

5. **API Access**: Ensure the backend API at `https://state-bank-of-india.onrender.com` is accessible or deploy your own instance.

## Deployment

* **Backend**: Deployed on Render at `https://state-bank-of-india.onrender.com`.
* **Frontend**: Currently runs locally with Streamlit; can be deployed on platforms like Heroku or Render for public access.
* **Status**: Live as of August 20, 2025, 12:49 PM IST.

## Achievements

* Successfully implemented a full-featured banking dashboard with real-time balance updates and secure transactions.
* Integrated OTP verification and fraud detection, enhancing security.
* Created a visually appealing interface with custom CSS and animations.
* Achieved seamless communication between frontend and backend via API calls.

## Limitations and Future Improvements

* **Scalability**: Current setup may struggle with a large user base; consider optimizing database queries or using a cloud solution like AWS.
* **Error Handling**: Some exceptions could be better caught and explained; automated testing could improve reliability.
* **API Efficiency**: Transaction history returns a string format; refactoring to return JSON would streamline parsing.
* **Future Work**: Add mobile support, advanced analytics, and multi-factor authentication.

## Challenges and Resolutions

* **Database Connectivity**: Resolved by configuring JDBC drivers and handling SQL exceptions.
* **UI Issues**: Fixed unclickable buttons by embedding them directly in the layout.
* **Transaction History Parsing**: Addressed string-formatted API responses by parsing into a DataFrame.
* **Security**: Improved with rate limiting for OTP requests and strong password enforcement.

## Contributing

Feel free to contribute to NexBank! Fork the repository, create a new branch, and submit a pull request with your improvements. Issues and feature requests are welcome via the GitHub Issues tab.

## License

This project is open-source under the MIT License. See the `LICENSE` file for details.

## Acknowledgments

* Thanks to the Streamlit community for the interactive framework.
* Appreciation to the Render platform for hosting the backend.
* Inspired by modern banking needs and futuristic design trends.

---

*Last Updated: August 20, 2025, 12:49 PM IST*
