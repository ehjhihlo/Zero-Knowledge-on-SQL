# Zero-Knowledge-on-SQL
Final project of course EE 5178: Database Management System – from SQL to NoSQL

  Databases play a crucial role in various applications, handling vast amounts of private data. However, concerns about data privacy and the reliability of query answers have emerged as users seek assurances from data providers without disclosing their own records. Historically, zero-knowledge proofs suffered from significant inefficiencies, limiting their practicality in complex applications. However, recent advancements by the cryptography community, such as Zero-Knowledge Succinct Non-interactive ARguments of Knowledge (ZK-SNARK) protocols, have significantly improved their efficiency.  

  In this project, we employ ZK-SNARK to implement aggregation functions in SQL, specifically focusing on the average, variance, and quantilecalculations. Our implementation utilizes the ZK-SNARK library in Python and SQLite, showcasing the feasibility of integrating zero-knowledge proofs into SQL for aggregation functions. By exploring the possibilities offered by ZK-SNARK in SQL, we aim to lay the foundation for secure and privacy-preserving data analysis, enhancing user trust in the reliability and privacy of query results.

Video are available from [here](https://www.youtube.com/watch?v=-QkWIDQqHU4)

## File Structure

```
Root
  ├── report.pdf: Written report
  ├── sql_final_code
  |     ├── crawl_data.ipynb: for crawling NBA 2022-23 player stats
  |     ├── NBA.csv: NBA 2022-23 player stats
  |     ├── total_and_avg_list.py: Zn-SNARK on sum and average calculation
  |     ├── var.py: Zn-SNARK on variance and standard deviation calculation
  |     ├── pr.py: Zn-SNARK on pr calculation
  |     ├── sql_final.ipynb: demo code
  ├── requirements.txt 
```

## Install Python-libsnark

```
pip install python-libsnark==0.3.2
```
