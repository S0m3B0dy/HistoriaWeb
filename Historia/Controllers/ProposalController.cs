using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.Entity;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using Historia.Models;

namespace Historia.Controllers
{
    [Authorize]
    public class ProposalController : Controller
    {

        // GET: Proposal
        public ActionResult Index()
        {
            string connectionString = string.Empty;
            connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
            if (String.IsNullOrEmpty(connectionString))
                throw new ApplicationException("No ConnectionString was found in the application settings.");

            List<ProposalModel> proposals = new List<ProposalModel>();
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                using (SqlCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandType = CommandType.Text;
                    cmd.CommandText = "SELECT * FROM Proposals";

                    try
                    {
                        cmd.Connection.Open();

                        using (SqlDataReader rdr = cmd.ExecuteReader())
                        {
                            while (rdr.Read())
                            {
                                ProposalModel pm = new ProposalModel();

                                pm.Id = rdr.GetInt32(rdr.GetOrdinal("Id"));
                                pm.ProposalName = rdr.GetString(rdr.GetOrdinal("ProposalName"));
                                pm.ProposalDescriptionUrl = rdr.GetString(rdr.GetOrdinal("ProposalDescriptionUrl"));
                                pm.PaymentDate = rdr.GetDateTime(rdr.GetOrdinal("PaymentDate"));
                                pm.PaymentAddress = rdr.GetString(rdr.GetOrdinal("PaymentAddress"));
                                pm.ProposalDescription = rdr.GetString(rdr.GetOrdinal("ProposalDescription"));
                                pm.ProposedByUserName = rdr.GetString(rdr.GetOrdinal("ProposedByUserName"));

                                proposals.Add(pm);
                            }
                        }
                    }
                    finally
                    {
                        cmd.Connection.Close();
                    }
                }

            }


            return View(proposals);
        }

        // GET: Proposal/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Proposal/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "Id,ProposalName,ProposalDescriptionUrl,PaymentDate,NumberOfPayments,PaymentAddress,PaymentAmount")] ProposalModel proposalModel)
        {
            if (ModelState.IsValid)
            {
                return RedirectToAction("Index");
            }

            return View(proposalModel);
        }


    }
}
