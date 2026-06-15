function StatCard({ title, value }) {
    return (
        <div style={{
            background: "rgba(255, 255, 255, 0.05)",
            backdropFilter: "blur(10px)",
            WebkitBackdropFilter: "blur(10px)",
            border: "1px solid rgba(255, 255, 255, 0.1)",
            borderRadius: "16px",
            padding: "20px",
            margin: "10px",
            boxShadow: "0 4px 30px rgba(0, 0, 0, 0.1)",
            transition: "transform 0.3s ease, boxShadow 0.3s ease",
            cursor: "pointer"
        }}
        onMouseEnter={(e) => {
            e.currentTarget.style.transform = "translateY(-5px)";
            e.currentTarget.style.boxShadow = "0 8px 30px rgba(88, 166, 255, 0.2)";
        }}
        onMouseLeave={(e) => {
            e.currentTarget.style.transform = "translateY(0)";
            e.currentTarget.style.boxShadow = "0 4px 30px rgba(0, 0, 0, 0.1)";
        }}>   
            <h3 style={{ margin: "0 0 10px 0", color: "#8b949e", fontSize: "1rem", fontWeight: "500" }}>{title}</h3>
            <p style={{ margin: "0", fontSize: "2rem", fontWeight: "700", color: "#f0f6fc" }}>{value}</p>     
        </div>
    );
}
export default StatCard;