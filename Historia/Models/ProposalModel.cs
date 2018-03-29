using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Historia.Models
{
    public class ProposalModel
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [Display(Name = "Title")]
        public string ProposalName { get; set; }

        [Required]
        [Display(Name = "Description")]
        [DataType(DataType.MultilineText)]
        public string ProposalDescription { get; set; }

        [Required]
        [Display(Name = "Project URL")]
        public string ProposalDescriptionUrl { get; set; }

        [Required]
        [Display(Name = "Payment Date")]
        public DateTime PaymentDate { get; set; }

        [Required]
        [Display(Name = "Number of Payments")]
        public int NumberOfPayments { get; set; }

        [Required]
        [Display(Name = "Payment Address")]
        public string PaymentAddress { get; set; }

        [Required]
        [Display(Name = "Payment Amount")]
        public decimal PaymentAmount { get; set; }

        [HiddenInput(DisplayValue = false)]
        public string ProposedByUserName { get; set; }
    }
}